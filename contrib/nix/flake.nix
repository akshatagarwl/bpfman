{
  description = "";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils, }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            go_1_21
            go-tools
            golangci-lint
            gopls
            gofumpt
            golines
            gci
            hadolint
            clang_16
            llvmPackages_16.bintools-unwrapped
            bpftools
            ebpf-verifier
          ];
        };
      });
}
