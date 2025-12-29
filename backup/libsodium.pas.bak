unit libsodium;

{$mode objfpc}{$H+}
{$PACKRECORDS C}

interface

uses
  ctypes;

const
  // Nom de la librairie native
  {$IFDEF Windows}
    SODIUM_LIB = 'libsodium.dll';
  {$ELSE}
    SODIUM_LIB = 'libsodium.so';
  {$ENDIF}

  // Taille du MAC (crypto_secretbox)
  crypto_secretbox_macbytes = 16;

  // crypto_pwhash algos et paramètres (scrypt interactive = ce que rclone utilise)
  crypto_pwhash_ALG_DEFAULT = 2; // scryptsalsa208sha256

  // Ces valeurs sont celles du profil "interactive" pour scrypt
  crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE = 524288;    // 2^19
  crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE = 16777216;  // 16 MiB

// Initialisation de libsodium
function sodium_init: cint; cdecl; external SODIUM_LIB;

// crypto_secretbox_open_easy
// m = message déchiffré, c = MAC + ciphertext, clen = longueur de c
// n = nonce (24 octets), k = clé (32 octets)
function crypto_secretbox_open_easy(
  m: pcuchar;
  const c: pcuchar;
  clen: culonglong;
  const n: pcuchar;
  const k: pcuchar
): cint; cdecl; external SODIUM_LIB;

// crypto_pwhash pour dériver une clé depuis password + salt
function crypto_pwhash(
  out_key: pcuchar;
  out_key_len: culonglong;
  const passwd: PAnsiChar;
  passwd_len: culonglong;
  const salt: pcuchar;
  opslimit: culonglong;
  memlimit: csize_t;
  alg: cint
): cint; cdecl; external SODIUM_LIB;

function crypto_pwhash_scryptsalsa208sha256_ll(
  const passwd: pcuchar;
  passwdlen: csize_t;
  const salt: pcuchar;
  saltlen: csize_t;
  N: culonglong;
  r: cuint;
  p: cuint;
  buf: pcuchar;
  buflen: csize_t
): cint; cdecl; external SODIUM_LIB;


implementation

end.

