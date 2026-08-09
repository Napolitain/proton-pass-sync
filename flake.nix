{
  description = "One-way Proton Pass to GNU pass synchronization for an encrypted offline cache";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

    home-manager = {
      url = "github:nix-community/home-manager/release-26.05";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      home-manager,
      ...
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = nixpkgs.lib.genAttrs systems;

      mkPkgs = system: import nixpkgs { inherit system; };
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = mkPkgs system;
          proton-pass-sync = pkgs.callPackage ./nix/package.nix { };
        in
        {
          inherit proton-pass-sync;
          default = proton-pass-sync;
        }
      );

      apps = forAllSystems (system: {
        proton-pass-sync = {
          type = "app";
          program = "${self.packages.${system}.proton-pass-sync}/bin/proton-pass-sync";
          meta.description = "Synchronize Proton Pass custom fields into GNU pass";
        };

        default = self.apps.${system}.proton-pass-sync;
      });

      checks = forAllSystems (
        system:
        let
          pkgs = mkPkgs system;
        in
        {
          package = self.packages.${system}.proton-pass-sync;

          home-manager = import ./nix/tests/home-manager.nix {
            inherit home-manager pkgs;
            module = self.homeManagerModules.default;
            package = self.packages.${system}.proton-pass-sync;
          };
        }
      );

      homeManagerModules = {
        proton-pass-sync = import ./nix/home-manager.nix { inherit self; };
        default = self.homeManagerModules.proton-pass-sync;
      };
    };
}
