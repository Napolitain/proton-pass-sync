{
  stdenv,
  fetchurl,
  autoPatchelfHook,
}:
stdenv.mkDerivation {
  pname = "proton-pass-cli";
  version = "2.3.3";
  src = fetchurl {
    url = "https://proton.me/download/pass-cli/2.3.3/pass-cli-linux-x86_64";
    sha256 = "b5b49a8b3fd0af8830c0c1979f28ea0c90ccece73f59023a8bca8245d4b68da9";
  };
  dontUnpack = true;
  nativeBuildInputs = [ autoPatchelfHook ];
  buildInputs = [ stdenv.cc.cc.lib ];
  installPhase = ''install -Dm755 "$src" "$out/bin/pass-cli"'';
  meta.platforms = [ "x86_64-linux" ];
}
