Select TblSourceA_2000i_missing.ssn,TblSourceA_2000i_missing.fn,TblSourceA_2000i_missing.ln, TblSourceA_2000i_missing.zip, TblSourceB_2000i_missing.ssn, TblSourceB_2000i_missing.fn, TblSourceB_2000i_missing.ln, TblSourceB_2000i_missing.zip
From TblSourceA_2000i_missing INNER JOIN TblSourceB_2000i_missing ON TblSourceA_2000i_missing.ssn_pk=TblSourceB_2000i_missing.ssn_pk 
WHERE TblSourceA_2000i_missing.ssn_pk NOT IN (select left_ssn_pk from Scenario_Missing_1i_ATTR_DECT)
LIMIT 0,1500;