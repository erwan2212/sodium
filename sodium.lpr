program sodium;

{$mode objfpc}{$H+}

uses
  SysUtils, Classes, ctypes, libsodium,urclonedecrypt;

   var
    key32: TKey32;
    i:byte;
    file_in:string;
    sr: TSearchRec;

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

procedure DecryptOneFile(const file_in: string);
var
  file_out: string;
begin
  if SameText(ExtractFileExt(file_in), '.bin') then
    file_out := ChangeFileExt(file_in, '')
  else
    file_out := ChangeFileExt(file_in, '.dec');

  Writeln(file_in + ' -> ' + file_out);

  try
    DecryptRcloneFileChunked64K(file_in, file_out, key32);
  except
    on e: Exception do
      Writeln('Erreur: ', e.Message);
  end;
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

  file_in := ExpandFileName(ParamStr(3));
  Writeln('Input détecté : ', file_in);

      if DirectoryExists(file_in) then
      begin
        Writeln('Mode dossier');

        file_in := IncludeTrailingPathDelimiter(file_in);

        if FindFirst(file_in + '*', faAnyFile, sr) = 0 then
        begin
          repeat
            if (sr.Name <> '.') and (sr.Name <> '..') then
              if (sr.Attr and faDirectory) = 0 then
                DecryptOneFile(file_in + sr.Name);
          until FindNext(sr) <> 0;

          FindClose(sr);
        end;
      end
      else
      begin
        Writeln('Mode fichier');
        DecryptOneFile(file_in);
      end;



end.

