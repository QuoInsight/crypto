<%@ Page language="C#" Debug="true"%>
<%@ Assembly Src="decrypt.cs" %>
<HTML>
<HEAD>
  <META http-equiv=Content-Type content="text/html; charset=utf-8">
</HEAD>
<BODY STYLE='margin:5px'>

<form method=post enctype="multipart/form-data" action="<%=Request.ServerVariables["SCRIPT_NAME"]%>">
  <input type=file name=file1><input type=submit>
</form>

<%
  // below is the .Net 2.0 legacy synchronous way to it, should use Request.Content.ReadAsMultipartAsync where possible
  System.Web.HttpFileCollection uploadedFiles = Request.Files;
  for (int i = 0; i < uploadedFiles.Count; i++) {
    if (uploadedFiles[i].ContentLength > 0) {
      Response.Write("[ " + System.IO.Path.GetFileName(uploadedFiles[i].FileName) + " ]<br>");
      Response.Write("[ " + uploadedFiles[i].ContentLength + " byte(s)]<br>");
      byte[] encryptedBytes = new byte[uploadedFiles[i].InputStream.Length];
      /*
        using (System.IO.MemoryStream memoryStream = new System.IO.MemoryStream()) {
          uploadedFiles[i].InputStream.CopyTo(memoryStream); // only supported under .NET 4 and above
          encryptedBytes = memoryStream.ToArray();
        }
      */
      int bytesRead = uploadedFiles[i].InputStream.Read(encryptedBytes, 0, uploadedFiles[i].ContentLength);

      String decryptedText = decryptNamespace.decryptClass.decryptAes256(encryptedBytes, "?????");

      Response.Write("<textarea disabled name=responseText cols=120 rows=25");
      Response.Write(" style='background-color:#DBE1F1'>\n");
      Response.Write( Server.HtmlEncode(decryptedText) );
      Response.Write("</textarea>\n");
      Response.Write("<br>\n");
    }
  }
%>

</BODY>
</HTML>