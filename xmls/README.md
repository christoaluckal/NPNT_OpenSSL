# These are the XMLs that are used in the entire operation. <br>
## key: C14N = Canonicalized <br>
1.	`bk.xml` : Backup of `codec14n.xml`
2.	`codec14n.xml` : C14N form of SignedInfo. **Has a newline at end **
3.	`correct.xml` : Signed XML document generated from `permission.xml` using signXML
4.	`cPI.xml` : C14N form of `permission.xml`.  **Has no a newline at end **. Generated using `xml_proc.cpp`
5.	`cSI.xml` : C14N form of SignedInfo.  **Has no a newline at end **.  Generated using `xml_proc.cpp`
6.	`fin_signed.xml` : Backup of `correct.xml`
7.	`permission.xml` : Base XML document that is being signed.
8.	`pugi_PI.xml` : Base form of `permission.xml`. Generated using `xml_proc.cpp`
9.	`pugi_SI.xml` : Base form of SignedInfo. Generated using `xml_proc.cpp`
