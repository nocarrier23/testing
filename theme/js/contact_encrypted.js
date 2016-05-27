
function check()
{
  var i = this.info.document.t.elements[0].value.indexOf(szErrName);
  if (i == 0 || !this.info.document.t.elements[0].value)
  {
    this.info.document.t.elements[0].value = szErrName;
    return false;
  }
  i = this.info.document.t.elements[1].value.indexOf(szErrMail);
  if (i == 0 || !isEmail(this.info.document.t.elements[1].value))
  {
    this.info.document.t.elements[1].value = szErrMail;
    return false;
  }
  i = this.info.document.t.elements[2].value.indexOf(szErrSubj);
  if (i == 0 || !this.info.document.t.elements[2].value)
  {
    this.info.document.t.elements[2].value = szErrSubj;
    return false;
  }
  return true;
}

function EncryptSend(enc)
{
  if(!check()) return false;

  var msg = this.info.document.t.elements[3].value;

  if(msg.indexOf('-----BEGIN PGP MESSAGE-----') >= 0)
  {
    if(enc) return false;
  }
  else
  {
    if (this.info.document.t.elements[4].value == "1")
    {
      this.info.document.t.elements[3].value = '\nSubject: '
        + this.info.document.t.elements[2].value + '\n\n' + msg;
      this.info.document.t.elements[2].value = '';
    }

    if (enc) this.info.document.t.elements[3].value = '\n'
      + doEncrypt(keyid,keytype,pubkey,this.info.document.t.elements[3].value);
  }
  this.info.document.t.submit();
  if(!enc) this.info.document.t.elements[3].value = msg;

  if (this.info.document.t.elements[5].value.length == 0)
  {
    this.info.document.t.elements[0].value = '';
    this.info.document.t.elements[1].value = '';
    this.info.document.t.elements[2].value = szAck;
  }
  return true;
}

function isEmail(str)
{
  var supported = 0;
  if (window.RegExp)
  {
    var tempStr = "a";
    var tempReg = new RegExp(tempStr);
    if (tempReg.test(tempStr)) supported = 1;
  }
  if (!supported) return (str.indexOf(".") > 2) && (str.indexOf("@") > 0);

  var r1 = new RegExp("(@.*@)|(\\.\\.)|(@\\.)|(^\\.)");
  var r2 = new RegExp("^.+\\@(\\[?)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,4}|[0-9]{1,4})(\\]?)$");
  return (!r1.test(str) && r2.test(str));
}

function confirmOk()
{
  this.info.document.write(szAck);
}
