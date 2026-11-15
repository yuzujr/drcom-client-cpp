{
  description = "DRCOM client for JLU — C++20 implementation";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      version = pkgs.lib.strings.removeSuffix "\n" (builtins.readFile ./VERSION);
    in
    {

      nixosModules.default = import ./nix/module.nix { inherit self; };

      # ── Package ────────────────────────────────────────────────────────────
      packages.${system}.default = pkgs.stdenv.mkDerivation {
        pname = "drcom-client-cpp";
        inherit version;
        src = ./.;

        nativeBuildInputs = [ pkgs.cmake ];
        nativeCheckInputs = [ pkgs.python3 ];
        doCheck = true;

        meta = {
          description = "DRCOM 802.1X client for JLU";
          homepage = "https://github.com/yuzujr/drcom-client-cpp";
          license = pkgs.lib.licenses.mit;
          mainProgram = "drcom_client";
          platforms = pkgs.lib.platforms.linux;
        };
      };

      # ── Dev shell ──────────────────────────────────────────────────────────
      devShells.${system}.default = pkgs.mkShell.override { stdenv = pkgs.clangStdenv; } {
        packages = with pkgs; [
          cmake
          ninja
          clang-tools
          python3
        ];
      };
    };
}
