program sodium;

{$mode objfpc}{$H+}

uses
  SysUtils, Classes, ctypes, libsodium,urclonedecrypt;

   var
    key32: TKey32;
    i:byte;
    filename:string;

    function RcloneDecryptFileNameObfuscate(const encName: string;
                                            const password, salt: string): string;
    var
      dataKey: TKey32;
      nameKey: TKey32;
      nameTweak: TKey16;
    begin
      // Dérive les clés comme rclone
      DeriveRcloneKeys(password, salt, dataKey, nameKey, nameTweak);

      // Déobfusque le segment
      Result := DeobfuscateSegment(encName, nameKey);
    end;

begin
  writeln('sodium.exe password salt filename');
  if paramcount < 3 then exit;
  if sodium_init() < 0 then raise Exception.Create('libsodium init failed');
  writeln('sodium_init ok');
  //rclone reveal password (from rclone.conf) to obtain the clear text password and salt
  DeriveRcloneKeys(paramstr(1), paramstr(2), key32);
  writeln('DeriveRcloneKeys ok');
  for i := 0 to High(key32) do Write(IntToHex(key32[i], 2));
  writeln();
  filename:=paramstr(3);
  writeln('filename='+filename);
  DecryptRcloneFileChunked64K(filename, 'dec.bin', key32);
  writeln('output=dec.bin');
end.

