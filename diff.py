import argparse

def find_nop_boundary(target_lines, offset):
  for i in range(offset, len(target_lines)):
      if "nop" in target_lines[i]:
        for j in range(i+1, len(target_lines)):
          if "nop" in target_lines[j]:
            return (i+1, j-1)
  return (-1, -1)

def dump_section(target_lines, low, high):
  for i in range(low, high):
    print(target_lines[i].strip().split("\t"))

def write_dotnet(target_lines, low, high, dotnetf):
  for i in range(low, high+1):
    tl = target_lines[i].strip()
    if tl[0] == ";" or tl[0] == 'G':
      continue
    dotnetf.write(" ".join(tl.split()))
    dotnetf.write("\n")

def write_llvm(target_lines, low, high, llvmf):
  for i in range(low, high+1):
    toks = target_lines[i].split("\t")
    address = toks[0].split(" ")
    address = address[1:]
    address_str = "".join(address).upper()
    toks[0] = address_str
    outstr = ' '.join(toks).strip()
    llvmf.write(outstr)
    llvmf.write("\n")


def do_main(args):
  with open(args.input_file, "r") as inpf, open(args.dotnet_out, "w") as dotnetf, open(args.llvm_out, "w") as llvmf:
    in_target_method = False
    target_lines = []
    for line in inpf:
      if "Assembly listing" in line and args.method in line:
        in_target_method = True
      if "Assembly listing" in line and args.method not in line:
        if in_target_method:
          break
        in_target_method = False

      if in_target_method:
        target_lines.append(line)

    (dotnet_low_ind, dotnet_high_ind) = find_nop_boundary(target_lines, 0)
    if dotnet_low_ind == -1:
      raise Exception("failed to find nop boundary for .net jit code")

    (llvm_low_ind, llvm_high_ind) = find_nop_boundary(target_lines, dotnet_high_ind+5)
    if llvm_low_ind == -1:
      raise Exception("failed to find nop boundary for llvm jit code")

    # Handle the .net side
    write_dotnet(target_lines, dotnet_low_ind, dotnet_high_ind, dotnetf)
    write_llvm(target_lines, llvm_low_ind, llvm_high_ind, llvmf)








if __name__ == "__main__":
  parser = argparse.ArgumentParser(
    prog='diff',
    description='Extract an cleaner diffable unit test dump of a combined NET/LLVM disasm'
    )

  parser.add_argument('input_file')
  parser.add_argument('method')
  parser.add_argument('--dotnet_out', default='dotnet.asm')
  parser.add_argument('--llvm_out', default='llvm.asm')

  args = parser.parse_args()

  do_main(args)
