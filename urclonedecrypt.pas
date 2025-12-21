unit urclonedecrypt;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, ctypes, libsodium;

type
  TKey16 = array[0..15] of Byte;
  TKey32 = array[0..31] of Byte;

procedure DeriveRcloneKeys(const password, password2: string; out keyContent: TKey32);
procedure DeriveRcloneKeys(const password, salt: string;
                           out dataKey: TKey32;
                           out nameKey: TKey32;
                           out nameTweak: TKey16); overload;
function DeobfuscateSegment(const obf: string; const nameKey: TKey32): string;
//procedure DecryptRcloneFile(const inFile, outFile: string; const key: TKey32);
procedure DecryptRcloneFileChunked64K(const inFile, outFile: string; const key: TKey32);

implementation

const
  RCLONE_MAGIC: array[0..7] of Byte = (
    Ord('R'), Ord('C'), Ord('L'), Ord('O'),
    Ord('N'), Ord('E'), 0, 0
  );
  CHUNK_PLAINTEXT_MAX = 65536; // 64 KiB

// Convertit un uint64 en little-endian dans dest[0..7]
procedure Uint64ToLEInto(aValue: QWord; dest: PByte);
var
  i: Integer;
begin
  for i := 0 to 7 do
  begin
    dest^ := Byte(aValue and $FF);
    aValue := aValue shr 8;
    Inc(dest);
  end;
end;


procedure DeriveRcloneKeys0(const password, password2: string; out keyContent: TKey32);
var
  pwd, salt: TBytes;
begin
  pwd := BytesOf(password);
  salt := BytesOf(password2);


  if crypto_pwhash(
       @keyContent[0], SizeOf(keyContent),
       PAnsiChar(@pwd[0]), Length(pwd),
       @salt[0],
       crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
       crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE,
       crypto_pwhash_ALG_DEFAULT
     ) <> 0 then
    raise Exception.Create('Key derivation failed');
end;

// Dérivation rclone : scrypt LL (16384, 8, 1)
procedure DeriveRcloneKeys(const password, password2: string; out keyContent: TKey32);
var
  pwdBytes, saltBytes: TBytes;
  res: cint;
begin
  // rclone : scrypt N=16384, r=8, p=1, keyLen = 32
  pwdBytes  := BytesOf(password);
  saltBytes := BytesOf(password2);

  if (Length(pwdBytes) = 0) or (Length(saltBytes) = 0) then
    raise Exception.Create('Password and salt must not be empty');

  res := crypto_pwhash_scryptsalsa208sha256_ll(
           pcuchar(@pwdBytes[0]), Length(pwdBytes),
           pcuchar(@saltBytes[0]), Length(saltBytes),
           16384, 8, 1,
           pcuchar(@keyContent[0]), SizeOf(keyContent)  // 32 octets
         );

  if res <> 0 then
    raise Exception.Create('Key derivation failed (scrypt LL)');
end;

procedure DeriveRcloneKeys(const password, salt: string;
                           out dataKey: TKey32;
                           out nameKey: TKey32;
                           out nameTweak: TKey16); overload;
var
  keyBuf: array[0..79] of Byte; // 32 + 32 + 16
  saltBytes: TBytes;
  i: Integer;
begin
  // Salt par défaut de rclone
  if salt = '' then
  begin
    SetLength(saltBytes, 16);
    saltBytes[0] := $A8; saltBytes[1] := $0D; saltBytes[2] := $F4; saltBytes[3] := $3A;
    saltBytes[4] := $8F; saltBytes[5] := $BD; saltBytes[6] := $03; saltBytes[7] := $08;
    saltBytes[8] := $A7; saltBytes[9] := $CA; saltBytes[10] := $B8; saltBytes[11] := $3E;
    saltBytes[12] := $58; saltBytes[13] := $1F; saltBytes[14] := $86; saltBytes[15] := $B1;
  end
  else
    saltBytes := BytesOf(salt);

  if password = '' then
  begin
    FillChar(keyBuf, SizeOf(keyBuf), 0);
  end
  else
  begin
    // rclone : N=16384, r=8, p=1
    if crypto_pwhash_scryptsalsa208sha256_ll(
         PByte(password), Length(password),
         @saltBytes[0], Length(saltBytes),
         16384, 8, 1,
         @keyBuf[0], 80
       ) <> 0 then
      raise Exception.Create('scrypt_ll failed');
  end;

  Move(keyBuf[0],  dataKey[0],   32);
  Move(keyBuf[32], nameKey[0],   32);
  Move(keyBuf[64], nameTweak[0], 16);
end;

{
Dans rclone, il existe 3 modes de chiffrement des noms :
Mode	Description	Exemple
off	pas de chiffrement, juste suffixe .bin	photo.jpg.bin
obfuscate	rotation simple, préfixe 123. ou !.	42.abcdEF
standard	chiffrement AES‑EME + encodage base32/base64/base32768	mvhcmd1a30jgupoqlr7cela41g
}
function DeobfuscateSegment(const obf: string; const nameKey: TKey32): string;
var
  before, after: string;
  p: Integer;
  dir, thisdir: Integer;
  r: WideChar;
  i, posVal, newRune, base: Integer;
  inQuote: Boolean;
  resultStr: UnicodeString;
begin
  if obf = '' then
    Exit('');

  // Trouve "nombre." ou "!."
  p := Pos('.', obf);
  if p = 0 then
    raise Exception.Create('Not an obfuscated name');

  before := Copy(obf, 1, p-1);
  after  := Copy(obf, p+1, Length(obf));

  // Cas spécial : "!.xxx"
  if before = '!' then
    Exit(after);

  // Convertit le nombre
  if not TryStrToInt(before, dir) then
    raise Exception.Create('Invalid obfuscation prefix');

  // Ajoute nameKey pour retrouver la vraie rotation
  for i := 0 to 31 do
    dir := dir + nameKey[i];

  resultStr := '';
  inQuote := False;

  for i := 1 to Length(after) do
  begin
    r := after[i];

    if inQuote then
    begin
      resultStr := resultStr + r;
      inQuote := False;
      Continue;
    end;

    if r = '!' then
    begin
      inQuote := True;
      Continue;
    end;

    // Chiffres
    if (r >= '0') and (r <= '9') then
    begin
      thisdir := (dir mod 9) + 1;
      newRune := Ord('0') + (Ord(r) - Ord('0') - thisdir);
      while newRune < Ord('0') do
        newRune := newRune + 10;
      r := WideChar(newRune);
      resultStr := resultStr + r;
      Continue;
    end;

    // Lettres ASCII
    if ((r >= 'A') and (r <= 'Z')) or ((r >= 'a') and (r <= 'z')) then
    begin
      thisdir := (dir mod 25) + 1;

      // Position dans A-Za-z
      posVal := Ord(r) - Ord('A');
      if posVal >= 26 then
        posVal := posVal - 6; // lower case

      posVal := posVal - thisdir;
      while posVal < 0 do
        posVal := posVal + 52;

      if posVal >= 26 then
        posVal := posVal + 6;

      r := WideChar(Ord('A') + posVal);
      resultStr := resultStr + r;
      Continue;
    end;

    // Latin-1
    if (Ord(r) >= $A0) and (Ord(r) <= $FF) then
    begin
      thisdir := (dir mod 95) + 1;
      newRune := $A0 + (Ord(r) - $A0 - thisdir);
      while newRune < $A0 do
        newRune := newRune + 96;
      r := WideChar(newRune);
      resultStr := resultStr + r;
      Continue;
    end;

    // Unicode > 0x100
    if Ord(r) >= $100 then
    begin
      thisdir := (dir mod 127) + 1;
      base := Ord(r) - (Ord(r) mod 256);
      newRune := base + (Ord(r) - base - thisdir);
      while newRune < base do
        newRune := newRune + 256;
      r := WideChar(newRune);
      resultStr := resultStr + r;
      Continue;
    end;

    // Sinon, inchangé
    resultStr := resultStr + r;
  end;

  Result := resultStr;
end;




// Déchiffrement chunké rclone
procedure DecryptRcloneFileChunked64K(const inFile, outFile: string; const key: TKey32);
const
  CHUNK_PLAINTEXT_SIZE = 64 * 1024; // 64 KiB
  RCLONE_MAGIC_STR     = 'RCLONE'#0#0;
var
  fsIn, fsOut: TFileStream;
  header: array[0..7] of Byte;
  fileNonce: array[0..23] of Byte;
  nonce: array[0..23] of Byte;
  macBytes: Integer;
  remaining: Int64;
  cipherBuf, plainBuf: TBytes;
  toRead, cipherLen, plainLen: Integer;
  i: Integer;

  procedure IncrementNonce(var n: array of Byte);
  var
    idx: Integer;
  begin
    // compteur little-endian sur 24 octets (comme cipher.go : carry(0))
    for idx := 0 to High(n) do
    begin
      n[idx] := (n[idx] + 1) and $FF;
      if n[idx] <> 0 then
        Break; // pas de retenue -> on s'arrête
    end;
  end;

begin
  macBytes := crypto_secretbox_macbytes; // 16 normalement

  fsIn := TFileStream.Create(inFile, fmOpenRead or fmShareDenyWrite);
  try
    if fsIn.Size < SizeOf(header) + SizeOf(fileNonce) + macBytes then
      raise Exception.Create('File too short to be a valid rclone crypt file');

    // 1) Header
    fsIn.ReadBuffer(header[0], SizeOf(header));
    // Vérif "RCLONE\0\0"
    for i := 0 to 7 do
      if header[i] <> Byte(RCLONE_MAGIC_STR[i + 1]) then
        raise Exception.Create('Invalid Rclone header');

    // 2) Nonce fichier (24 octets)
    fsIn.ReadBuffer(fileNonce[0], SizeOf(fileNonce));
    // nonce courant = nonce initial
    Move(fileNonce[0], nonce[0], SizeOf(fileNonce));

    // 3) Prépare la sortie
    fsOut := TFileStream.Create(outFile, fmCreate);
    try
      // 4) Boucle sur les blocs jusqu'à EOF
      while fsIn.Position < fsIn.Size do
      begin
        remaining := fsIn.Size - fsIn.Position;

        // On lit au maximum un bloc complet : MAC + 64 KiB ciphertext
        toRead := macBytes + CHUNK_PLAINTEXT_SIZE;
        if remaining < toRead then
          toRead := remaining;

        cipherLen := toRead;
        if cipherLen <= macBytes then
          raise Exception.Create('Block too small to contain MAC and data');

        SetLength(cipherBuf, cipherLen);
        fsIn.ReadBuffer(cipherBuf[0], cipherLen);

        plainLen := cipherLen - macBytes;
        SetLength(plainBuf, plainLen);

        // 5) Déchiffrer ce bloc avec le nonce courant
        if crypto_secretbox_open_easy(
             @plainBuf[0],
             @cipherBuf[0],
             cipherLen,
             @nonce[0],
             @key[0]
           ) <> 0 then
          raise Exception.Create('Decryption failed (MAC) on current block');

        // 6) Écrire le plaintext du bloc
        fsOut.WriteBuffer(plainBuf[0], plainLen);

        // 7) Incrémenter le nonce pour le bloc suivant
        IncrementNonce(nonce);
      end;
    finally
      fsOut.Free;
    end;

  finally
    fsIn.Free;
  end;
end;





//non chunké / 64kb max
procedure DecryptRcloneFile(const inFile, outFile: string; const key: TKey32);
var
  fsIn, fsOut: TFileStream;
  header: array[0..7] of Byte;
  fileNonce: array[0..23] of Byte;
  macBytes: Integer;
  remaining: Int64;
  cipherBuf, plainBuf: TBytes;
  cipherLen, plainLen: Integer;
begin
  macBytes := crypto_secretbox_macbytes; // 16

  fsIn := TFileStream.Create(inFile, fmOpenRead or fmShareDenyWrite);
  try
    if fsIn.Size < SizeOf(header) + SizeOf(fileNonce) + macBytes then
      raise Exception.Create('File too short to be a valid rclone crypt file');

    // 1) Header
    fsIn.ReadBuffer(header[0], SizeOf(header));
    if not CompareMem(@header[0], @RCLONE_MAGIC[0], SizeOf(header)) then
      raise Exception.Create('Invalid Rclone header');

    // 2) Nonce (24 octets)
    fsIn.ReadBuffer(fileNonce[0], SizeOf(fileNonce));

    // 3) Le reste = MAC + ciphertext d’un seul bloc
    remaining := fsIn.Size - fsIn.Position;
    if remaining <= macBytes then
      raise Exception.Create('Ciphertext too short');

    cipherLen := remaining;
    SetLength(cipherBuf, cipherLen);
    fsIn.ReadBuffer(cipherBuf[0], cipherLen);

    plainLen := cipherLen - macBytes;
    SetLength(plainBuf, plainLen);

    // 4) Un seul secretbox pour tout le fichier
    if crypto_secretbox_open_easy(
         @plainBuf[0],
         @cipherBuf[0],
         cipherLen,
         @fileNonce[0],
         @key[0]
       ) <> 0 then
      raise Exception.Create('Decryption failed (MAC)');

    // 5) Écrire le clair
    fsOut := TFileStream.Create(outFile, fmCreate);
    try
      fsOut.WriteBuffer(plainBuf[0], plainLen);
    finally
      fsOut.Free;
    end;

  finally
    fsIn.Free;
  end;
end;


end.

