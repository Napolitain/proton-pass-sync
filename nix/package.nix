{
  lib,
  rustPlatform,
  gnupg,
  makeWrapper,
  pass,
}:

rustPlatform.buildRustPackage {
  pname = "proton-pass-sync";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.lock
      ../Cargo.toml
      ../src
      ../tests
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;

  strictDeps = true;
  nativeBuildInputs = [ makeWrapper ];
  nativeCheckInputs = [
    gnupg
    pass
  ];

  postFixup = ''
    wrapProgram "$out/bin/proton-pass-sync" \
      --prefix PATH : ${
        lib.makeBinPath [
          gnupg
          pass
        ]
      }
  '';

  meta = {
    description = "One-way Proton Pass to GNU pass synchronization for an encrypted offline cache";
    homepage = "https://github.com/Napolitain/proton-pass-sync";
    license = lib.licenses.mit;
    mainProgram = "proton-pass-sync";
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
}
