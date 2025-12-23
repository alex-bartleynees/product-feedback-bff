{
  description = "A Nix-flake-based C# development environment";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { self, nixpkgs }:
    let
      supportedSystems =
        [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forEachSupportedSystem = f:
        nixpkgs.lib.genAttrs supportedSystems (system:
          f {
            pkgs = import nixpkgs {
              inherit system;
              config = { allowUnfree = true; };
            };
          });
    in {
      devShells = forEachSupportedSystem ({ pkgs }: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            (with dotnetCorePackages; combinePackages [ sdk_10_0 ])
            csharp-ls
            #mono
            (buildDotnetGlobalTool {
              pname = "dotnet-ef";
              version = "9.0.0";
              nugetHash = "sha256-/Ru/H2WXX/SCqF2s0M1DJkaw+6Nikm+ccrveqiOXggA=";
            })
          ];

          shellHook = ''
            # Ensure needed directories exist
            mkdir -p "$HOME/.nuget/NuGet"

            export DOTNET_ROOT="${pkgs.dotnetCorePackages.sdk_10_0}"
            export DOTNET_CLI_TELEMETRY_OPTOUT=1

            echo ".NET $(dotnet --version) development environment ready"
          '';
        };
      });
    };
}
