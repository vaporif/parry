{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane = {
      url = "github:ipetkov/crane";
    };
  };

  outputs = {
    nixpkgs,
    fenix,
    crane,
    ...
  }: let
    systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    forAllSystems = f:
      nixpkgs.lib.genAttrs systems (system:
        f {
          pkgs = nixpkgs.legacyPackages.${system};
          fenixPkgs = fenix.packages.${system};
          craneLib =
            (crane.mkLib nixpkgs.legacyPackages.${system}).overrideToolchain
            fenix.packages.${system}.stable.toolchain;
        });
  in {
    homeManagerModules.default = import ./nix/hm-module.nix;

    packages = forAllSystems ({
      pkgs,
      craneLib,
      ...
    }: let
      src = craneLib.cleanCargoSource ./.;
      commonArgs = {
        inherit src;
        pname = "parry";
        strictDeps = true;
        buildInputs = pkgs.lib.optionals pkgs.stdenv.isDarwin [
          pkgs.libiconv
          pkgs.apple-sdk_15
        ];
      };
      cargoArtifacts = craneLib.buildDepsOnly commonArgs;
    in {
      default = craneLib.buildPackage (commonArgs
        // {
          inherit cargoArtifacts;
          meta = {
            description = "Prompt injection scanner for Claude Code";
            license = pkgs.lib.licenses.mit;
            mainProgram = "parry";
          };
        });
    });

    devShells = forAllSystems ({
      pkgs,
      fenixPkgs,
      ...
    }: let
      toolchain = fenixPkgs.stable.withComponents [
        "cargo"
        "clippy"
        "rustc"
        "rustfmt"
        "rust-src"
        "rust-analyzer"
      ];
    in {
      default = pkgs.mkShell {
        packages =
          [
            toolchain
            pkgs.just
            pkgs.taplo
            pkgs.typos
            pkgs.actionlint
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.apple-sdk_15
          ];

        env = {
          RUST_BACKTRACE = "1";
          RUST_SRC_PATH = "${toolchain}/lib/rustlib/src/rust/library";
        };
      };
    });
  };
}
