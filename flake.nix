{
  description = "DRCOM client for JLU — C++20 implementation";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {

      # ── Package ────────────────────────────────────────────────────────────
      packages.${system}.default = pkgs.stdenv.mkDerivation {
        pname = "drcom-client-cpp";
        version = "0.1.0";
        src = ./.;

        nativeBuildInputs = [ pkgs.cmake ];

        installPhase = ''
          runHook preInstall
          install -Dm755 src/drcom_client $out/bin/drcom_client
          install -Dm644 ${./config/drcom_jlu.conf} \
            $out/share/drcom-client-cpp/config/drcom_jlu.conf
          runHook postInstall
        '';

        meta = {
          description = "DRCOM 802.1X client for JLU";
          homepage = "https://github.com/yuzujr/drcom-client-cpp";
          license = pkgs.lib.licenses.mit;
          platforms = pkgs.lib.platforms.linux;
        };
      };

      # ── Dev shell ──────────────────────────────────────────────────────────
      devShells.${system}.default = pkgs.mkShell.override { stdenv = pkgs.clangStdenv; } {
        packages = with pkgs; [
          cmake
          ninja
          clang-tools
        ];

        shellHook = ''
          echo "drcom-client-cpp dev shell"
          echo "  cmake -B build && cmake --build build"
        '';
      };
    };
}
