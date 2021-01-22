# NPNT_OpenSSL
NPNT Compliance using OpenSSL CMD/CXX API

## Follow the method to verify signature <br>
Method
1.  `cd pys/` <br>
  **a.  CD into the python scripts**
2. `python3 sign.py` <br>
  a.  Execute the `sign.py` script which will create `fin_signed.xml` in `xmls/` directory
3.  `cd ..p` <br>
  **a.  CD into the main directory**
4. `./check_signature.sh` <br>
  a.  Make sure that the script has proper permissions.
