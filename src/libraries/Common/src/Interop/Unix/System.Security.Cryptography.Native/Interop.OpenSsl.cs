// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class OpenSsl
    {
        // This cache size affects number of TLS Session Tickets each SslCtx will cache, not the number of SslCtx instances.
        // Special value of 0 means unlimited, -1 means the implementation (OpenSSL) default, which is currently 20 * 1024.
        private const string TlsCacheSizeCtxName = "System.Net.Security.TlsCacheSize";
        private const string TlsCacheSizeEnvironmentVariable = "DOTNET_SYSTEM_NET_SECURITY_TLSCACHESIZE";
        private const int DefaultTlsCacheSizeClient = 500; // since we keep only one TLS Session per hostname, 500 should be enough to cover most scenarios
        private const int DefaultTlsCacheSizeServer = -1; // use implementation default
        private const SslProtocols FakeAlpnSslProtocol = (SslProtocols)1;   // used to distinguish server sessions with ALPN
        private static readonly Lazy<string[]> s_defaultSigAlgs = new(GetDefaultSignatureAlgorithms);

        private sealed class SafeSslContextCache : SafeHandleCache<SslContextCacheKey, SafeSslContextHandle> { }

        private static readonly SafeSslContextCache s_sslContexts = new();

        internal readonly struct SslContextCacheKey : IEquatable<SslContextCacheKey>
        {
            private const int ThumbprintSize = 64; // SHA512 size

            public readonly bool IsClient;
            public readonly ReadOnlyMemory<byte> CertificateThumbprints;
            public readonly SslProtocols SslProtocols;

            public SslContextCacheKey(bool isClient, SslProtocols sslProtocols, SslStreamCertificateContext? certContext)
            {
                IsClient = isClient;
                SslProtocols = sslProtocols;

                CertificateThumbprints = ReadOnlyMemory<byte>.Empty;

                if (certContext != null)
                {
                    int certCount = 1 + certContext.IntermediateCertificates.Count;
                    byte[] certificateThumbprints = new byte[certCount * ThumbprintSize];

                    bool success = certContext.TargetCertificate.TryGetCertHash(HashAlgorithmName.SHA512, certificateThumbprints.AsSpan(0, ThumbprintSize), out _);
                    Debug.Assert(success);

                    certCount = 1;
                    foreach (X509Certificate2 intermediate in certContext.IntermediateCertificates)
                    {
                        success = intermediate.TryGetCertHash(HashAlgorithmName.SHA512, certificateThumbprints.AsSpan(certCount * ThumbprintSize, ThumbprintSize), out _);
                        Debug.Assert(success);
                        certCount++;
                    }

                    CertificateThumbprints = certificateThumbprints;
                }
            }

            public override bool Equals(object? obj) => obj is SslContextCacheKey key && Equals(key);

            public bool Equals(SslContextCacheKey other) =>

                IsClient == other.IsClient &&
                CertificateThumbprints.Span.SequenceEqual(other.CertificateThumbprints.Span) &&
                SslProtocols == other.SslProtocols;

            public override int GetHashCode()
            {
                HashCode hash = default;

                hash.Add(IsClient);
                hash.AddBytes(CertificateThumbprints.Span);
                hash.Add(SslProtocols);

                return hash.ToHashCode();
            }
        }

        #region internal methods
        internal static SafeChannelBindingHandle? QueryChannelBinding(SafeSslHandle context, ChannelBindingKind bindingType)
        {
            Debug.Assert(
                bindingType != ChannelBindingKind.Endpoint,
                "Endpoint binding should be handled by EndpointChannelBindingToken");

            SafeChannelBindingHandle? bindingHandle;
            switch (bindingType)
            {
                case ChannelBindingKind.Unique:
                    bindingHandle = new SafeChannelBindingHandle(bindingType);
                    QueryUniqueChannelBinding(context, bindingHandle);
                    break;

                default:
                    // Keeping parity with windows, we should return null in this case.
                    bindingHandle = null;
                    break;
            }

            return bindingHandle;
        }

        private static readonly int s_cacheSizeOverride = GetCacheSize();

        private static int GetCacheSize()
        {
            string? value = AppContext.GetData(TlsCacheSizeCtxName) as string ?? Environment.GetEnvironmentVariable(TlsCacheSizeEnvironmentVariable);
            if (!int.TryParse(value, CultureInfo.InvariantCulture, out int cacheSize))
            {
                cacheSize = -1;
            }

            return cacheSize;
        }

        // This is helper function to adjust requested protocols based on CipherSuitePolicy and system capability.
        private static SslProtocols CalculateEffectiveProtocols(SslAuthenticationOptions sslAuthenticationOptions)
        {
            // make sure low bit is not set since we use it in context dictionary to distinguish use with ALPN
            Debug.Assert((sslAuthenticationOptions.EnabledSslProtocols & FakeAlpnSslProtocol) == 0);
            SslProtocols protocols = sslAuthenticationOptions.EnabledSslProtocols & ~((SslProtocols)1);

            if (!Interop.Ssl.Capabilities.Tls13Supported)
            {
                if (protocols != SslProtocols.None &&
                    CipherSuitesPolicyPal.WantsTls13(protocols))
                {
                    protocols &= ~SslProtocols.Tls13;
                }
            }
            else if (CipherSuitesPolicyPal.WantsTls13(protocols) &&
                CipherSuitesPolicyPal.ShouldOptOutOfTls13(sslAuthenticationOptions.CipherSuitesPolicy, sslAuthenticationOptions.EncryptionPolicy))
            {
                if (protocols == SslProtocols.None)
                {
                    // we are using default settings but cipher suites policy says that TLS 1.3
                    // is not compatible with our settings (i.e. we requested no encryption or disabled
                    // all TLS 1.3 cipher suites)
#pragma warning disable SYSLIB0039 // TLS 1.0 and 1.1 are obsolete
                    protocols = SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12;
#pragma warning restore SYSLIB0039
                }
                else
                {
                    // user explicitly asks for TLS 1.3 but their policy is not compatible with TLS 1.3
                    throw new SslException(
                        SR.Format(SR.net_ssl_encryptionpolicy_notsupported, sslAuthenticationOptions.EncryptionPolicy));
                }
            }

            if (CipherSuitesPolicyPal.ShouldOptOutOfLowerThanTls13(sslAuthenticationOptions.CipherSuitesPolicy))
            {
                if (!CipherSuitesPolicyPal.WantsTls13(protocols))
                {
                    // We cannot provide neither TLS 1.3 or non TLS 1.3, user disabled all cipher suites
                    throw new SslException(
                        SR.Format(SR.net_ssl_encryptionpolicy_notsupported, sslAuthenticationOptions.EncryptionPolicy));
                }

                protocols = SslProtocols.Tls13;
            }

            return protocols;
        }

        internal static SafeSslContextHandle GetOrCreateSslContextHandle(SslAuthenticationOptions sslAuthenticationOptions, bool allowCached)
        {
            SslProtocols protocols = CalculateEffectiveProtocols(sslAuthenticationOptions);

            if (!allowCached)
            {
                return AllocateSslContext(sslAuthenticationOptions, protocols, allowCached);
            }

            bool hasAlpn = sslAuthenticationOptions.ApplicationProtocols != null && sslAuthenticationOptions.ApplicationProtocols.Count != 0;

            SslProtocols serverProtocolCacheKey = protocols | (hasAlpn ? FakeAlpnSslProtocol : SslProtocols.None);

            var key = new SslContextCacheKey(
                sslAuthenticationOptions.IsClient,
                sslAuthenticationOptions.IsClient ? protocols : serverProtocolCacheKey,
                sslAuthenticationOptions.CertificateContext);
            return s_sslContexts.GetOrCreate(key, static (args) =>
            {
                var (sslAuthOptions, protocols, allowCached) = args;
                return AllocateSslContext(sslAuthOptions, protocols, allowCached);
            }, (sslAuthenticationOptions, protocols, allowCached));
        }

        // This essentially wraps SSL_CTX* aka SSL_CTX_new + setting
        internal static unsafe SafeSslContextHandle AllocateSslContext(SslAuthenticationOptions sslAuthenticationOptions, SslProtocols protocols, bool enableResume)
        {
            // Always use SSLv23_method, regardless of protocols.  It supports negotiating to the highest
            // mutually supported version and can thus handle any of the set protocols, and we then use
            // SetProtocolOptions to ensure we only allow the ones requested.
            SafeSslContextHandle sslCtx = Ssl.SslCtxCreate(Ssl.SslMethods.SSLv23_method);
            try
            {
                if (sslCtx.IsInvalid)
                {
                    throw CreateSslException(SR.net_allocate_ssl_context_failed);
                }

                Ssl.SslCtxSetProtocolOptions(sslCtx, protocols);

                if (sslAuthenticationOptions.EncryptionPolicy != EncryptionPolicy.RequireEncryption)
                {
                    // Sets policy and security level
                    if (!Ssl.SetEncryptionPolicy(sslCtx, sslAuthenticationOptions.EncryptionPolicy))
                    {
                        throw new SslException(SR.Format(SR.net_ssl_encryptionpolicy_notsupported, sslAuthenticationOptions.EncryptionPolicy));
                    }
                }

                ReadOnlySpan<byte> cipherList = CipherSuitesPolicyPal.GetOpenSslCipherList(sslAuthenticationOptions.CipherSuitesPolicy, protocols, sslAuthenticationOptions.EncryptionPolicy);
                Debug.Assert(cipherList.IsEmpty || cipherList[^1] == 0);

                byte[]? cipherSuites = CipherSuitesPolicyPal.GetOpenSslCipherSuites(sslAuthenticationOptions.CipherSuitesPolicy, protocols, sslAuthenticationOptions.EncryptionPolicy);
                Debug.Assert(cipherSuites == null || (cipherSuites.Length >= 1 && cipherSuites[cipherSuites.Length - 1] == 0));

                fixed (byte* cipherListStr = cipherList)
                fixed (byte* cipherSuitesStr = cipherSuites)
                {
                    if (!Ssl.SslCtxSetCiphers(sslCtx, cipherListStr, cipherSuitesStr))
                    {
                        Crypto.ErrClearError();
                        throw new PlatformNotSupportedException(SR.Format(SR.net_ssl_encryptionpolicy_notsupported, sslAuthenticationOptions.EncryptionPolicy));
                    }
                }

                // The logic in SafeSslHandle.Disconnect is simple because we are doing a quiet
                // shutdown (we aren't negotiating for session close to enable later session
                // restoration).
                //
                // If you find yourself wanting to remove this line to enable bidirectional
                // close-notify, you'll probably need to rewrite SafeSslHandle.Disconnect().
                // https://www.openssl.org/docs/manmaster/ssl/SSL_shutdown.html
                Ssl.SslCtxSetQuietShutdown(sslCtx);

                if (enableResume)
                {
                    if (sslAuthenticationOptions.IsServer)
                    {
                        Span<byte> contextId = stackalloc byte[32];
                        RandomNumberGenerator.Fill(contextId);
                        int cacheSize = s_cacheSizeOverride >= 0 ? s_cacheSizeOverride : DefaultTlsCacheSizeServer;
                        Ssl.SslCtxSetCaching(sslCtx, 1, cacheSize, contextId.Length, contextId, null, null);
                    }
                    else
                    {
                        int cacheSize = s_cacheSizeOverride >= 0 ? s_cacheSizeOverride : DefaultTlsCacheSizeClient;
                        int result = Ssl.SslCtxSetCaching(sslCtx, 1, cacheSize, 0, null, &NewSessionCallback, &RemoveSessionCallback);
                        Debug.Assert(result == 1);
                        sslCtx.EnableSessionCache();
                    }
                }
                else
                {
                    Ssl.SslCtxSetCaching(sslCtx, 0, -1, 0, null, null, null);
                }

                if (sslAuthenticationOptions.IsServer && sslAuthenticationOptions.ApplicationProtocols != null && sslAuthenticationOptions.ApplicationProtocols.Count != 0)
                {
                    Interop.Ssl.SslCtxSetAlpnSelectCb(sslCtx, &AlpnServerSelectCallback, IntPtr.Zero);
                }

                if (sslAuthenticationOptions.CertificateContext != null && sslAuthenticationOptions.IsServer)
                {
                    SetSslCertificate(sslCtx, sslAuthenticationOptions.CertificateContext.CertificateHandle, sslAuthenticationOptions.CertificateContext.KeyHandle);

                    if (sslAuthenticationOptions.CertificateContext.IntermediateCertificates.Count > 0)
                    {
                        if (!Ssl.AddExtraChainCertificates(sslCtx, sslAuthenticationOptions.CertificateContext.IntermediateCertificates))
                        {
                            throw CreateSslException(SR.net_ssl_use_cert_failed);
                        }
                    }

                    if (sslAuthenticationOptions.CertificateContext.OcspStaplingAvailable)
                    {
                        Ssl.SslCtxSetDefaultOcspCallback(sslCtx);
                    }
                }
                if (SslKeyLogger.IsEnabled)
                {
                    Ssl.SslCtxSetKeylogCallback(sslCtx, &KeyLogCallback);
                }
            }
            catch
            {
                sslCtx.Dispose();
                throw;
            }

            return sslCtx;
        }

        internal static void UpdateClientCertificate(SafeSslHandle ssl, SslAuthenticationOptions sslAuthenticationOptions)
        {
            // Disable certificate selection callback. We either got certificate or we will try to proceed without it.
            Interop.Ssl.SslSetClientCertCallback(ssl, 0);

            if (sslAuthenticationOptions.CertificateContext == null)
            {
                return;
            }

            Debug.Assert(sslAuthenticationOptions.CertificateContext.CertificateHandle != null);
            Debug.Assert(sslAuthenticationOptions.CertificateContext.KeyHandle != null);

            int retVal = Ssl.SslUseCertificate(ssl, sslAuthenticationOptions.CertificateContext.CertificateHandle);
            if (1 != retVal)
            {
                throw CreateSslException(SR.net_ssl_use_cert_failed);
            }

            retVal = Ssl.SslUsePrivateKey(ssl, sslAuthenticationOptions.CertificateContext.KeyHandle);
            if (1 != retVal)
            {
                throw CreateSslException(SR.net_ssl_use_private_key_failed);
            }

            if (sslAuthenticationOptions.CertificateContext.IntermediateCertificates.Count > 0)
            {
                if (!Ssl.AddExtraChainCertificates(ssl, sslAuthenticationOptions.CertificateContext.IntermediateCertificates))
                {
                    throw CreateSslException(SR.net_ssl_use_cert_failed);
                }
            }
        }

        // This essentially wraps SSL* SSL_new()
        internal static SafeSslHandle AllocateSslHandle(SslAuthenticationOptions sslAuthenticationOptions)
        {
            SafeSslHandle? sslHandle = null;
            bool cacheSslContext = sslAuthenticationOptions.AllowTlsResume && !SslStream.DisableTlsResume && sslAuthenticationOptions.EncryptionPolicy == EncryptionPolicy.RequireEncryption && sslAuthenticationOptions.CipherSuitesPolicy == null;

            if (cacheSslContext)
            {
                if (sslAuthenticationOptions.IsClient)
                {
                    // We don't support client resume on old OpenSSL versions.
                    // We don't want to try on empty TargetName or IP Address since hostname is our key.
                    // If we already have CertificateContext, then we know which cert the user wants to use and we can cache.
                    // The only client auth scenario where we can't cache is when user provides a cert callback and we don't know
                    // beforehand which cert will be used. and wan't to avoid resuming session created with different certificate.
                    if (!Interop.Ssl.Capabilities.Tls13Supported ||
                       string.IsNullOrEmpty(sslAuthenticationOptions.TargetHost) ||
                       IPAddress.IsValid(sslAuthenticationOptions.TargetHost) ||
                       (sslAuthenticationOptions.CertificateContext == null && sslAuthenticationOptions.CertSelectionDelegate != null))
                    {
                        cacheSslContext = false;
                    }
                }
                else
                {
                    // Server should always have certificate
                    Debug.Assert(sslAuthenticationOptions.CertificateContext != null);
                    if (sslAuthenticationOptions.CertificateContext == null)
                    {
                        cacheSslContext = false;
                    }
                }
            }

            // We do not touch the SSL_CTX after we create and configure SSL
            // objects, and SSL object created later in this function will keep an
            // outstanding up-ref on SSL_CTX.
            //
            // For uncached SafeSslContextHandles, the handle will be disposed and closed.
            // Cached SafeSslContextHandles are returned with increaset rent count so that
            // Dispose() here will not close the handle.
            using SafeSslContextHandle sslCtxHandle = GetOrCreateSslContextHandle(sslAuthenticationOptions, cacheSslContext);

            GCHandle alpnHandle = default;
            try
            {
                sslHandle = SafeSslHandle.Create(sslCtxHandle, sslAuthenticationOptions.IsServer);
                Debug.Assert(sslHandle != null, "Expected non-null return value from SafeSslHandle.Create");
                if (sslHandle.IsInvalid)
                {
                    sslHandle.Dispose();
                    throw CreateSslException(SR.net_allocate_ssl_context_failed);
                }

                if (cacheSslContext)
                {
                    // For non-cached SSL_CTX instances, we free the `sslCtxHandle`
                    // after creating the SSL instance and don't use it again. We don't
                    // access it afterwards and OpenSSL has internal refcount which
                    // keeps it alive until the last SSL using it is freed.
                    //
                    // For cached SSL_CTX instances, we want to keep an outstanding
                    // up-ref to indicate that it is in use and does not get
                    // evicted from the cache.
                    //
                    // This call should always succeed because we already
                    // increased the rent count when getting the context from
                    // the cache.
                    bool success = sslCtxHandle.TryAddRentCount();
                    Debug.Assert(success);
                    sslHandle.SslContextHandle = sslCtxHandle;
                }

                if (!sslAuthenticationOptions.AllowRsaPssPadding || !sslAuthenticationOptions.AllowRsaPkcs1Padding)
                {
                    ConfigureSignatureAlgorithms(sslHandle, sslAuthenticationOptions.AllowRsaPssPadding, sslAuthenticationOptions.AllowRsaPkcs1Padding);
                }

                if (sslAuthenticationOptions.ApplicationProtocols != null && sslAuthenticationOptions.ApplicationProtocols.Count != 0)
                {
                    if (sslAuthenticationOptions.IsServer)
                    {
                        Debug.Assert(Interop.Ssl.SslGetData(sslHandle) == IntPtr.Zero);
                        alpnHandle = GCHandle.Alloc(sslAuthenticationOptions.ApplicationProtocols);
                        Interop.Ssl.SslSetData(sslHandle, GCHandle.ToIntPtr(alpnHandle));
                        sslHandle.AlpnHandle = alpnHandle;
                    }
                    else
                    {
                        if (Interop.Ssl.SslSetAlpnProtos(sslHandle, sslAuthenticationOptions.ApplicationProtocols) != 0)
                        {
                            throw CreateSslException(SR.net_alpn_config_failed);
                        }
                    }
                }

                if (sslAuthenticationOptions.IsClient)
                {
                    if (!string.IsNullOrEmpty(sslAuthenticationOptions.TargetHost) && !IPAddress.IsValid(sslAuthenticationOptions.TargetHost))
                    {
                        // Similar to windows behavior, set SNI on openssl by default for client context, ignore errors.
                        if (!Ssl.SslSetTlsExtHostName(sslHandle, sslAuthenticationOptions.TargetHost))
                        {
                            Crypto.ErrClearError();
                        }

                        if (cacheSslContext)
                        {
                            sslCtxHandle.TrySetSession(sslHandle, sslAuthenticationOptions.TargetHost);
                        }
                    }

                    // relevant to TLS 1.3 only: if user supplied a client cert or cert callback,
                    // advertise that we are willing to send the certificate post-handshake.
                    if (sslAuthenticationOptions.CertificateContext != null ||
                        sslAuthenticationOptions.ClientCertificates?.Count > 0 ||
                        sslAuthenticationOptions.CertSelectionDelegate != null)
                    {
                        Ssl.SslSetPostHandshakeAuth(sslHandle, 1);
                    }

                    // Set client cert callback, this will interrupt the handshake with SecurityStatusPalErrorCode.CredentialsNeeded
                    // if server actually requests a certificate.
                    Ssl.SslSetClientCertCallback(sslHandle, 1);
                }
                else // sslAuthenticationOptions.IsServer
                {
                    if (sslAuthenticationOptions.RemoteCertRequired)
                    {
                        Ssl.SslSetVerifyPeer(sslHandle);
                    }

                    if (sslAuthenticationOptions.CertificateContext != null)
                    {
                        if (sslAuthenticationOptions.CertificateContext.Trust?._sendTrustInHandshake == true)
                        {
                            SslCertificateTrust trust = sslAuthenticationOptions.CertificateContext!.Trust!;
                            X509Certificate2Collection certList = (trust._trustList ?? trust._store!.Certificates);

                            Debug.Assert(certList != null);
                            Span<IntPtr> handles = certList.Count <= 256 ?
                                stackalloc IntPtr[256] :
                                new IntPtr[certList.Count];

                            for (int i = 0; i < certList.Count; i++)
                            {
                                handles[i] = certList[i].Handle;
                            }

                            if (!Ssl.SslAddClientCAs(sslHandle, handles.Slice(0, certList.Count)))
                            {
                                // The method can fail only when the number of cert names exceeds the maximum capacity
                                // supported by STACK_OF(X509_NAME) structure, which should not happen under normal
                                // operation.
                                Debug.Fail("Failed to add issuer to trusted CA list.");
                            }
                        }

                        byte[]? ocspResponse = sslAuthenticationOptions.CertificateContext.GetOcspResponseNoWaiting();

                        if (ocspResponse != null)
                        {
                            Ssl.SslStapleOcsp(sslHandle, ocspResponse);
                        }
                    }
                }
            }
            catch
            {
                if (alpnHandle.IsAllocated)
                {
                    alpnHandle.Free();
                }

                throw;
            }

            return sslHandle;
        }

        internal static string[] GetDefaultSignatureAlgorithms()
        {
            ushort[] rawAlgs = Interop.Ssl.GetDefaultSignatureAlgorithms();

            // The mapping below is taken from STRINT_PAIR signature_tls13_scheme_list and other
            // data structures in OpenSSL source code (apps/lib/s_cb.c file).
            static string ConvertAlg(ushort rawAlg) => rawAlg switch
            {
                0x0201 => "rsa_pkcs1_sha1",
                0x0203 => "ecdsa_sha1",
                0x0401 => "rsa_pkcs1_sha256",
                0x0403 => "ecdsa_secp256r1_sha256",
                0x0501 => "rsa_pkcs1_sha384",
                0x0503 => "ecdsa_secp384r1_sha384",
                0x0601 => "rsa_pkcs1_sha512",
                0x0603 => "ecdsa_secp521r1_sha512",
                0x0804 => "rsa_pss_rsae_sha256",
                0x0805 => "rsa_pss_rsae_sha384",
                0x0806 => "rsa_pss_rsae_sha512",
                0x0807 => "ed25519",
                0x0808 => "ed448",
                0x0809 => "rsa_pss_pss_sha256",
                0x080a => "rsa_pss_pss_sha384",
                0x080b => "rsa_pss_pss_sha512",
                0x081a => "ecdsa_brainpoolP256r1_sha256",
                0x081b => "ecdsa_brainpoolP384r1_sha384",
                0x081c => "ecdsa_brainpoolP512r1_sha512",
                0x0904 => "mldsa44",
                0x0905 => "mldsa65",
                0x0906 => "mldsa87",
                _ =>
                    Tls12HashName((byte)(rawAlg >> 8)) is string hashName &&
                    Tls12SignatureName((byte)rawAlg) is string sigName
                        ? $"{sigName}+{hashName}"
                        : $"0x{rawAlg:x4}" // this will cause the setter to fail, but at least we get a string representation in the log.
            };

            static string? Tls12HashName(byte raw) => raw switch
            {
                0x00 => "none",
                0x01 => "MD5",
                0x02 => "SHA1",
                0x03 => "SHA224",
                0x04 => "SHA256",
                0x05 => "SHA384",
                0x06 => "SHA512",
                _ => null
            };

            static string? Tls12SignatureName(byte raw) => raw switch
            {
                0x00 => "anonymous",
                0x01 => "RSA",
                0x02 => "DSA",
                0x03 => "ECDSA",
                _ => null
            };

            string[] result = Array.ConvertAll(rawAlgs, ConvertAlg);
            if (NetEventSource.Log.IsEnabled())
            {
                NetEventSource.Info(null, $"Default signature algorithms: {string.Join(":", result)}");
            }

            return result;
        }

        internal static unsafe void ConfigureSignatureAlgorithms(SafeSslHandle sslHandle, bool enablePss, bool enablePkcs1)
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(512);
            try
            {
                int index = 0;

                foreach (string alg in s_defaultSigAlgs.Value)
                {
                    // includes both rsa_pss_pss_* and rsa_pss_rsae_*
                    if (alg.StartsWith("rsa_pss_", StringComparison.Ordinal) && !enablePss)
                    {
                        continue;
                    }

                    if (alg.StartsWith("rsa_pkcs1_", StringComparison.Ordinal) && !enablePkcs1)
                    {
                        continue;
                    }

                    // Ensure we have enough space for the algorithm name, separator and null terminator.
                    EnsureSize(ref buffer, index + alg.Length + 2);

                    if (index > 0)
                    {
                        buffer[index++] = (byte)':';
                    }

                    index += Encoding.UTF8.GetBytes(alg, buffer.AsSpan(index));
                }
                buffer[index] = 0; // null terminator

                int ret;
                fixed (byte* pBuffer = buffer)
                {
                    ret = Interop.Ssl.SslSetSigalgs(sslHandle, pBuffer);
                    if (ret != 1)
                    {
                        throw CreateSslException(SR.Format(SR.net_ssl_set_sigalgs_failed, "server"));
                    }

                    ret = Interop.Ssl.SslSetClientSigalgs(sslHandle, pBuffer);
                    if (ret != 1)
                    {
                        throw CreateSslException(SR.Format(SR.net_ssl_set_sigalgs_failed, "client"));
                    }
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            static void EnsureSize(ref byte[] buffer, int size)
            {
                if (buffer.Length < size)
                {
                    // there are a few dozen algorithms total in existence, so we don't expect the buffer to grow too large.
                    Debug.Assert(size < 10 * 1024, "The buffer should not grow too large.");

                    byte[] oldBuffer = buffer;
                    buffer = ArrayPool<byte>.Shared.Rent(buffer.Length * 2);
                    oldBuffer.AsSpan().CopyTo(buffer);
                    ArrayPool<byte>.Shared.Return(oldBuffer);
                }
            }
        }

        internal static SecurityStatusPal SslRenegotiate(SafeSslHandle sslContext, out byte[]? outputBuffer)
        {
            int ret = Interop.Ssl.SslRenegotiate(sslContext, out Ssl.SslErrorCode errorCode);

            outputBuffer = Array.Empty<byte>();
            if (ret != 1)
            {
                return new SecurityStatusPal(SecurityStatusPalErrorCode.InternalError, GetSslError(ret, errorCode));
            }
            return new SecurityStatusPal(SecurityStatusPalErrorCode.OK);
        }

        internal static SecurityStatusPalErrorCode DoSslHandshake(SafeSslHandle context, ReadOnlySpan<byte> input, ref ProtocolToken token)
        {
            token.Size = 0;
            Exception? handshakeException = null;

            if (input.Length > 0)
            {
                if (Ssl.BioWrite(context.InputBio!, ref MemoryMarshal.GetReference(input), input.Length) != input.Length)
                {
                    // Make sure we clear out the error that is stored in the queue
                    throw Crypto.CreateOpenSslCryptographicException();
                }
            }

            int retVal = Ssl.SslDoHandshake(context, out Ssl.SslErrorCode errorCode);
            if (retVal != 1)
            {
                if (errorCode == Ssl.SslErrorCode.SSL_ERROR_WANT_X509_LOOKUP)
                {
                    return SecurityStatusPalErrorCode.CredentialsNeeded;
                }

                if ((retVal != -1) || (errorCode != Ssl.SslErrorCode.SSL_ERROR_WANT_READ))
                {
                    Exception? innerError = GetSslError(retVal, errorCode);

                    // Handshake failed, but even if the handshake does not need to read, there may be an Alert going out.
                    // To handle that we will fall-through the block below to pull it out, and we will fail after.
                    handshakeException = new SslException(SR.Format(SR.net_ssl_handshake_failed_error, errorCode), innerError);
                }
            }

            int sendCount = Crypto.BioCtrlPending(context.OutputBio!);
            if (sendCount > 0)
            {
                token.EnsureAvailableSpace(sendCount);
                try
                {
                    sendCount = BioRead(context.OutputBio!, token.AvailableSpan, sendCount);
                }
                catch (Exception) when (handshakeException != null)
                {
                    // If we already have handshake exception, ignore any exception from BioRead().
                }
                finally
                {
                    if (sendCount <= 0)
                    {
                        // Make sure we clear out the error that is stored in the queue
                        Crypto.ErrClearError();
                        sendCount = 0;
                    }
                }
            }

            token.Size = sendCount;

            if (handshakeException != null)
            {
                throw handshakeException;
            }

            // in case of TLS 1.3 post-handshake authentication, SslDoHandhaske
            // may return SSL_ERROR_NONE while still expecting more data from
            // the client. Attempts to send app data in this state would result
            // in SSL_ERROR_WANT_READ from SslWrite, override the return status
            // to continue waiting for the rest of the TLS frames
            if (context.IsServer && token.Size == 0 && errorCode == Ssl.SslErrorCode.SSL_ERROR_NONE && Ssl.IsSslRenegotiatePending(context))
            {
                return SecurityStatusPalErrorCode.ContinueNeeded;
            }

            bool stateOk = Ssl.IsSslStateOK(context);
            if (stateOk)
            {
                context.MarkHandshakeCompleted();
            }

            return stateOk ? SecurityStatusPalErrorCode.OK : SecurityStatusPalErrorCode.ContinueNeeded;
        }

        internal static Ssl.SslErrorCode Encrypt(SafeSslHandle context, ReadOnlySpan<byte> input, ref ProtocolToken outToken)
        {
            int retVal = Ssl.SslWrite(context, ref MemoryMarshal.GetReference(input), input.Length, out Ssl.SslErrorCode errorCode);

            if (retVal != input.Length)
            {
                outToken.Size = 0;
                switch (errorCode)
                {
                    // indicate end-of-file
                    case Ssl.SslErrorCode.SSL_ERROR_ZERO_RETURN:
                    case Ssl.SslErrorCode.SSL_ERROR_WANT_READ:
                        break;

                    default:
                        throw new SslException(SR.Format(SR.net_ssl_encrypt_failed, errorCode), GetSslError(retVal, errorCode));
                }
            }
            else
            {
                int capacityNeeded = Crypto.BioCtrlPending(context.OutputBio!);
                outToken.EnsureAvailableSpace(capacityNeeded);
                retVal = BioRead(context.OutputBio!, outToken.AvailableSpan, capacityNeeded);

                if (retVal <= 0)
                {
                    // Make sure we clear out the error that is stored in the queue
                    Crypto.ErrClearError();
                    outToken.Size = 0;
                }
                else
                {
                    outToken.Size = retVal;
                }
            }

            return errorCode;
        }

        internal static int Decrypt(SafeSslHandle context, Span<byte> buffer, out Ssl.SslErrorCode errorCode)
        {
            BioWrite(context.InputBio!, buffer);

            int retVal = Ssl.SslRead(context, ref MemoryMarshal.GetReference(buffer), buffer.Length, out errorCode);
            if (retVal > 0)
            {
                return retVal;
            }

            switch (errorCode)
            {
                // indicate end-of-file
                case Ssl.SslErrorCode.SSL_ERROR_ZERO_RETURN:
                    break;

                case Ssl.SslErrorCode.SSL_ERROR_WANT_READ:
                    // update error code to renegotiate if renegotiate is pending, otherwise make it SSL_ERROR_WANT_READ
                    errorCode = Ssl.IsSslRenegotiatePending(context)
                        ? Ssl.SslErrorCode.SSL_ERROR_RENEGOTIATE
                        : Ssl.SslErrorCode.SSL_ERROR_WANT_READ;
                    break;

                case Ssl.SslErrorCode.SSL_ERROR_WANT_X509_LOOKUP:
                    // This happens in TLS 1.3 when server requests post-handshake authentication
                    // but no certificate is provided by client. We can process it the same way as
                    // renegotiation on older TLS versions
                    errorCode = Ssl.SslErrorCode.SSL_ERROR_RENEGOTIATE;
                    break;

                default:
                    throw new SslException(SR.Format(SR.net_ssl_decrypt_failed, errorCode), GetSslError(retVal, errorCode));
            }

            return 0;
        }

        internal static IntPtr GetPeerCertificate(SafeSslHandle context)
        {
            return Ssl.SslGetPeerCertificate(context);
        }

        internal static SafeSharedX509StackHandle GetPeerCertificateChain(SafeSslHandle context)
        {
            return Ssl.SslGetPeerCertChain(context);
        }

        #endregion

        #region private methods

        private static void QueryUniqueChannelBinding(SafeSslHandle context, SafeChannelBindingHandle bindingHandle)
        {
            bool sessionReused = Ssl.SslSessionReused(context);
            int certHashLength = context.IsServer ^ sessionReused ?
                                 Ssl.SslGetPeerFinished(context, bindingHandle.CertHashPtr, bindingHandle.Length) :
                                 Ssl.SslGetFinished(context, bindingHandle.CertHashPtr, bindingHandle.Length);

            if (0 == certHashLength)
            {
                throw CreateSslException(SR.net_ssl_get_channel_binding_token_failed);
            }

            bindingHandle.SetCertHashLength(certHashLength);
        }

#pragma warning disable IDE0060
        [UnmanagedCallersOnly]
        private static int VerifyClientCertificate(int preverify_ok, IntPtr x509_ctx_ptr)
        {
            // Full validation is handled after the handshake in VerifyCertificateProperties and the
            // user callback.  It's also up to those handlers to decide if a null certificate
            // is appropriate.  So just return success to tell OpenSSL that the cert is acceptable,
            // we'll process it after the handshake finishes.
            const int OpenSslSuccess = 1;
            return OpenSslSuccess;
        }
#pragma warning restore IDE0060

        [UnmanagedCallersOnly]
        private static unsafe int AlpnServerSelectCallback(IntPtr ssl, byte** outp, byte* outlen, byte* inp, uint inlen, IntPtr arg)
        {
            *outp = null;
            *outlen = 0;
            IntPtr sslData = Ssl.SslGetData(ssl);

            if (sslData == IntPtr.Zero)
            {
                return Ssl.SSL_TLSEXT_ERR_ALERT_FATAL;
            }

            GCHandle protocolHandle = GCHandle.FromIntPtr(sslData);
            if (!(protocolHandle.Target is List<SslApplicationProtocol> protocolList))
            {
                return Ssl.SSL_TLSEXT_ERR_ALERT_FATAL;
            }

            try
            {
                for (int i = 0; i < protocolList.Count; i++)
                {
                    var clientList = new Span<byte>(inp, (int)inlen);
                    while (clientList.Length > 0)
                    {
                        byte length = clientList[0];
                        Span<byte> clientProto = clientList.Slice(1, length);
                        if (clientProto.SequenceEqual(protocolList[i].Protocol.Span))
                        {
                            fixed (byte* p = &MemoryMarshal.GetReference(clientProto)) *outp = p;
                            *outlen = length;
                            return Ssl.SSL_TLSEXT_ERR_OK;
                        }

                        clientList = clientList.Slice(1 + length);
                    }
                }
            }
            catch
            {
                // No common application protocol was negotiated, set the target on the alpnHandle to null.
                // It is ok to clear the handle value here, this results in handshake failure, so the SslStream object is disposed.
                protocolHandle.Target = null;

                return Ssl.SSL_TLSEXT_ERR_ALERT_FATAL;
            }

            // No common application protocol was negotiated, set the target on the alpnHandle to null.
            // It is ok to clear the handle value here, this results in handshake failure, so the SslStream object is disposed.
            protocolHandle.Target = null;

            return Ssl.SSL_TLSEXT_ERR_ALERT_FATAL;
        }

        [UnmanagedCallersOnly]
        // Invoked from OpenSSL when new session is created.
        // We attached GCHandle to the SSL so we can find back SafeSslContextHandle holding the cache.
        // New session has refCount of 1.
        // If this function returns 0, OpenSSL will drop the refCount and discard the session.
        // If we return 1, the ownership is transferred to us and we will need to call SessionFree().
        private static unsafe int NewSessionCallback(IntPtr ssl, IntPtr session)
        {
            Debug.Assert(ssl != IntPtr.Zero);
            Debug.Assert(session != IntPtr.Zero);

            // remember if the session used a certificate, this information is used after
            // session resumption, the pointer is not being dereferenced and the refcount
            // is not going to be manipulated.
            IntPtr cert = Interop.Ssl.SslGetCertificate(ssl);
            Interop.Ssl.SslSessionSetData(session, cert);

            IntPtr ptr = Ssl.SslGetData(ssl);
            if (ptr != IntPtr.Zero)
            {
                GCHandle gch = GCHandle.FromIntPtr(ptr);
                IntPtr name = Ssl.SslGetServerName(ssl);
                Debug.Assert(name != IntPtr.Zero);

                SafeSslContextHandle? ctxHandle = gch.Target as SafeSslContextHandle;
                // There is no relation between SafeSslContextHandle and SafeSslHandle so the handle
                // may be released while the ssl session is still active.
                if (ctxHandle != null && ctxHandle.TryAddSession(name, session))
                {
                    // offered session was stored in our cache.
                    return 1;
                }
            }

            // OpenSSL will destroy session.
            return 0;
        }

        [UnmanagedCallersOnly]
        private static unsafe void RemoveSessionCallback(IntPtr ctx, IntPtr session)
        {
            Debug.Assert(ctx != IntPtr.Zero && session != IntPtr.Zero);

            IntPtr ptr = Ssl.SslCtxGetData(ctx);
            if (ptr == IntPtr.Zero)
            {
                // Same as above, SafeSslContextHandle could be released while OpenSSL still holds reference.
                return;
            }

            GCHandle gch = GCHandle.FromIntPtr(ptr);
            SafeSslContextHandle? ctxHandle = gch.Target as SafeSslContextHandle;
            if (ctxHandle == null)
            {
                return;
            }

            IntPtr name = Ssl.SessionGetHostname(session);
            Debug.Assert(name != IntPtr.Zero);
            ctxHandle.RemoveSession(name, session);
        }

        [UnmanagedCallersOnly]
        private static unsafe void KeyLogCallback(IntPtr ssl, char* line)
        {
            ReadOnlySpan<byte> data = MemoryMarshal.CreateReadOnlySpanFromNullTerminated((byte*)line);
            SslKeyLogger.WriteLineRaw(data);
        }

        private static int BioRead(SafeBioHandle bio, Span<byte> buffer, int count)
        {
            Debug.Assert(count >= 0);
            Debug.Assert(buffer.Length >= count);

            int bytes = Crypto.BioRead(bio, buffer);
            if (bytes != count)
            {
                throw CreateSslException(SR.net_ssl_read_bio_failed_error);
            }
            return bytes;
        }

        private static void BioWrite(SafeBioHandle bio, ReadOnlySpan<byte> buffer)
        {
            int bytes = Ssl.BioWrite(bio, ref MemoryMarshal.GetReference(buffer), buffer.Length);
            if (bytes != buffer.Length)
            {
                throw CreateSslException(SR.net_ssl_write_bio_failed_error);
            }
        }

        private static Exception? GetSslError(int result, Ssl.SslErrorCode retVal)
        {
            Exception? innerError;
            switch (retVal)
            {
                case Ssl.SslErrorCode.SSL_ERROR_SYSCALL:
                    ErrorInfo lastErrno = Sys.GetLastErrorInfo();
                    // Some I/O error occurred
                    innerError =
                        Crypto.ErrPeekError() != 0 ? Crypto.CreateOpenSslCryptographicException() : // crypto error queue not empty
                        result == 0 ? new EndOfStreamException() : // end of file that violates protocol
                        result == -1 && lastErrno.Error != Error.SUCCESS ? new IOException(lastErrno.GetErrorMessage(), lastErrno.RawErrno) : // underlying I/O error
                        null; // no additional info available
                    break;

                case Ssl.SslErrorCode.SSL_ERROR_SSL:
                    // OpenSSL failure occurred.  The error queue contains more details, when building the exception the queue will be cleared.
                    innerError = Interop.Crypto.CreateOpenSslCryptographicException();
                    break;

                default:
                    // No additional info available.
                    innerError = null;
                    break;
            }

            return innerError;
        }

        private static void SetSslCertificate(SafeSslContextHandle contextPtr, SafeX509Handle certPtr, SafeEvpPKeyHandle keyPtr)
        {
            Debug.Assert(certPtr != null && !certPtr.IsInvalid);
            Debug.Assert(keyPtr != null && !keyPtr.IsInvalid);

            int retVal = Ssl.SslCtxUseCertificate(contextPtr, certPtr);

            if (1 != retVal)
            {
                throw CreateSslException(SR.net_ssl_use_cert_failed);
            }

            retVal = Ssl.SslCtxUsePrivateKey(contextPtr, keyPtr);

            if (1 != retVal)
            {
                throw CreateSslException(SR.net_ssl_use_private_key_failed);
            }

            //check private key
            retVal = Ssl.SslCtxCheckPrivateKey(contextPtr);

            if (1 != retVal)
            {
                throw CreateSslException(SR.net_ssl_check_private_key_failed);
            }
        }

        internal static SslException CreateSslException(string message)
        {
            // Capture last error to be consistent with CreateOpenSslCryptographicException
            ulong errorVal = Crypto.ErrPeekLastError();
            Crypto.ErrClearError();
            string msg = SR.Format(message, Marshal.PtrToStringUTF8(Crypto.ErrReasonErrorString(errorVal)));
            return new SslException(msg, (int)errorVal);
        }

        #endregion

        #region Internal class

        internal sealed class SslException : Exception
        {
            public SslException(string? inputMessage)
                : base(inputMessage)
            {
            }

            public SslException(string? inputMessage, Exception? ex)
                : base(inputMessage, ex)
            {
            }

            public SslException(string? inputMessage, int error)
                : this(inputMessage)
            {
                HResult = error;
            }

            public SslException(int error)
                : this(SR.Format(SR.net_generic_operation_failed, error))
            {
                HResult = error;
            }
        }

        #endregion
    }
}
