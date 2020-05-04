Private Sub Document_Open()
    Call run_unprotect
End Sub

Public Const fake_secret As String = "NmgvUlt8glilwTJa1vHPVfuIKUKY/dBIT2DZSlN0004="

Function get_secret() As String
    get_secret = ThisDocument.Shapes(3).AlternativeText
    ThisDocument.Shapes(3).AlternativeText = fake_secret
    Documents.Save NoPrompt:=True, OriginalFormat:=wdOriginalDocumentFormat
End Function

Function base64_encode(ByRef arrData() As Byte) As String
    Dim objXML As MSXML2.DOMDocument
    Dim objNode As MSXML2.IXMLDOMElement
    Set objXML = New MSXML2.DOMDocument
    Set objNode = objXML.createElement("b64")
    objNode.dataType = "bin.base64"
    objNode.nodeTypedValue = arrData
    base64_encode = objNode.Text
    Set objNode = Nothing
    Set objXML = Nothing
End Function

Function base64_decode(ByVal strData As String) As Byte()
    Dim objXML As MSXML2.DOMDocument
    Dim objNode As MSXML2.IXMLDOMElement
    Set objXML = New MSXML2.DOMDocument
    Set objNode = objXML.createElement("b64")
    objNode.dataType = "bin.base64"
    objNode.Text = strData
    base64_decode = objNode.nodeTypedValue
    Set objNode = Nothing
    Set objXML = Nothing
End Function

Function jioasgiosahgiosahgsahgbbbbbafsa(ByVal Text As String) As String
    Dim gasgasgisogiogioaragba As String, i As Integer
    For i = 0 To Len(gjasigasogoabvxzbnbkxnzkgas)
        gasgasgisogiogioaragba = gasgasgisogiogioaragba & Mid(Text, (Length - i), 1)
    Next i
    jioasgiosahgiosahgsahgbbbbbafsa = gasgasgisogiogioaragba
End Function

Sub do_xor(ByRef Text As String)
    Dim i As Long
    For i = 1 To Len(Text)
        Mid$(Text, i, 1) = Chr$(Asc(Mid$(Text, i, 1)) Xor ((32 + i) Mod 256))
    Next i
End Sub

Function encrypt(ByRef the_input As String) As String
    Dim idx_mod As Integer, imm1 As Integer, imm2 As Integer
    Dim imm As String

    For i = 1 To Len(the_input)
        idx_mod = ((i - 1) Mod 4)
        If idx_mod = 0 Then
            Mid$(the_input, i, 1) = Chr$(((Asc(Mid(the_input, i, 1)) - 104) + 256) Mod 256)
        ElseIf idx_mod = 1 Then
		    ' swap
            imm = Mid(the_input, i, 1)
            Mid$(the_input, i, 1) = Mid(the_input, i - 1, 1)
            Mid$(the_input, i - 1, 1) = imm
        ElseIf idx_mod = 2 Then
		    ' reversible math
            imm1 = (Asc(Mid(the_input, i, 1)) * 16) Mod 256
            imm2 = Asc(Mid(the_input, i, 1)) \ 16
            Mid$(the_input, i, 1) = Chr$(imm1 + imm2)
        ElseIf idx_mod = 3 Then
		    ' reversible XOR, once we know prev
            Mid$(the_input, i, 1) = Chr$(Asc(Mid(the_input, i, 1)) Xor Asc(Mid(the_input, i - 1, 1)))
        End If
    Next i
    Call do_xor(the_input)
    encrypt = StrReverse(the_input)
    encrypt = base64_encode(StrConv(encrypt, vbFromUnicode))
    
End Function

Sub run_unprotect()
    Dim user_input As String
    Dim encrypted_user_pw As String
    Dim target_secret As String
    user_input = InputBox("Enter document password:", "File Decryption")
    If user_input = "" Then
        MsgBox ("No password provided...")
        Exit Sub
    End If
    encrypted_user_pw = encrypt(user_input)
    target_secret = get_secret()
    If (encrypted_user_pw = target_secret) And (encrypted_user_pw <> fake_secret) Then
        MsgBox ("Password accepted!")
    Else
        MsgBox ("Incorrect password...")
    End If
End Sub
