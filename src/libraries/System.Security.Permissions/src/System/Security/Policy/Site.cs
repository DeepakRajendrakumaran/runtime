// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Security.Policy
{
#if NET
    [Obsolete(Obsoletions.CodeAccessSecurityMessage, DiagnosticId = Obsoletions.CodeAccessSecurityDiagId, UrlFormat = Obsoletions.SharedUrlFormat)]
#endif
    public sealed partial class Site : EvidenceBase, IIdentityPermissionFactory
    {
        public Site(string name) { }
        public string Name { get { return null; } }
        public object Copy() { return null; }
        public static Site CreateFromUrl(string url) { return default(Site); }
        public IPermission CreateIdentityPermission(Evidence evidence) { return default(IPermission); }
        public override bool Equals(object o) => base.Equals(o);
        public override int GetHashCode() => base.GetHashCode();
        public override string ToString() => base.ToString();
    }
}
