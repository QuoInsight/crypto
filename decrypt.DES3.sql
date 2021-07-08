DECLARE

  FUNCTION decryptDES3 (
    piv_strHex VARCHAR2, piv_strKey VARCHAR2
  ) RETURN VARCHAR2 IS
    lr_decrypted_raw  RAW(2048);
  BEGIN
    lr_decrypted_raw := DBMS_CRYPTO.DECRYPT(
      src => piv_strHex,
      typ => DBMS_CRYPTO.DES3_CBC_PKCS5,
      key => UTL_RAW.CAST_TO_RAW(piv_strKey)
    );
    RETURN utl_raw.cast_to_varchar2(lr_decrypted_raw);
  EXCEPTION
    WHEN OTHERS THEN
      Dbms_Output.put_line('ERROR in decryptDES3():' || SQLERRM);
      RETURN NULL;
  END;

BEGIN

  Dbms_Output.put_line(
    decryptDES3(
      '37C0B43B770D46C2AEAF1D1E9A6AE2F51DD41E5CF1782B69',
      'XXXXXXXXXXXXXXXXXXXXXXXX'
    )
  );

END;
