
var nacl_factory;
var nacl;

var serverPKhex = "57d79a01456c7cbcc9dee2f90b11dc7f1f03bd0079632ecca99b20337d70901e";
var serverPK;

var clientKeypair; // XXX shouldn't be global
var nonce;
var noncehex;

function decodeServerKey() {
  serverPK = nacl.from_hex(serverPKhex);
}

function generateClientKeypair() {
  clientKeypair = nacl.crypto_box_keypair();
}

function loadClientKeypair(keypair) {
  clientKeypair = { boxPk: nacl.from_hex(keypair.slice(0,  64)),
                    boxSk: nacl.from_hex(keypair.slice(64, 128)) };
}

function storeClientKeypair() {
  var key = nacl.to_hex(clientKeypair.boxPk);
  key.concat(nacl.to_hex(clientKeypair.boxSk));
  return key;
}

$.getScript('https://ioerrror.github.io/jacobappelbaum.net/themes/js/nacl_factory.js')
  .done(
    function(script, textStatus) {
      nacl_factory = script;
    })
  .fail(
    function(jqxhr, settings, exception) {
      if (!!nacl_factory) {
        window.console.log("Error instantiating NaCl library: " + exception);
      }
    });

function resetForm() {
  $('#contactForm').trigger("reset");
}

function reportFailure() {
  $('#success').html("<div class='alert alert-danger'>");
  $('#success > .alert-danger').html("<button type='button' class='close' data-dismiss='alert' aria-hidden='true'>&times;")
    .append("</button>");
  $('#success > .alert-danger').append("<strong>Sorry, it seems that my mail server is not responding. Please try again later!");
  $('#success > .alert-danger').append('</div>');
  resetForm();
}

function reportSuccess() {
  $('#success').html("<div class='alert alert-success'>");
  $('#success > .alert-success').html("<button type='button' class='close' data-dismiss='alert' aria-hidden='true'>&times;")
    .append("</button>");
  $('#success > .alert-success')
    .append("<strong>Your message has been sent. </strong>");
  $('#success > .alert-success')
    .append('</div>');
  resetForm();
}

function beforeSubmit() {
  var name = $("input#name").val();
  var email = $("input#email").val();
  var key = $("input#keypair").val();
  var message = $("textarea#message").val();

  if (nonce) {
    window.console.log("We've already done this...");
  } else {
    nacl = nacl_factory.instantiate(16777216); // 16MB heap
    decodeServerKey();

    if (key) {
      loadClientKeypair(key);
    } else {
      generateClientKeypair();
      key = storeClientKeypair();
    }

    nonce = nacl.crypto_box_random_nonce();
    noncehex = nacl.to_hex(nonce);

    var pk = nacl.to_hex(clientKeypair.boxPk);
    var report = 'Name: ' + name + '\nEmail: ' + email +
                 '\nKey: ' + pk + '\nMessage: ' + message;
    var encoded = nacl.encode_utf8(report);
    var ciphertext = nacl.crypto_box(encoded, nonce,
                                     serverPK, clientKeypair.boxSk);
    var encrypted = nacl.to_hex(ciphertext);

    var text = "Your NaCl key is:\n\n" + key + "\n\nPlease keep it somewhere safe!";
    alert(text);
    //$("#keyModalBody").text(text);  // XXX make the fucking modal work
    //$("#keyModal").modal('show');

    $.ajax({
      url: "https://formspree.io/jacobsvictims@gmail.com",
      crossDomain: true,
      type: "POST",
      data: { publickey: pk, nonce: noncehex, message: encrypted },
      cache: false,
      success: function() {
        reportSuccess();
      },
      error: function(jqXHR, textStatus, errorThrown) {
        if (textStatus == "error") {
          reportSuccess(); // CORS error returned
        } else {
          reportFailure();
        };
      }
    });
  }
  return false;
};

$(function() {
    $("input,textarea").jqBootstrapValidation({
        preventSubmit: true,
        submitError: function($form, event, errors) {
            // additional error messages or events
        },
        submitSuccess: function($form, event) {
            event.preventDefault(); // prevent default submit behaviour
        },
        filter: function() {
            return $(this).is(":visible");
        },
    });

    $("a[data-toggle=\"tab\"]").click(function(e) {
        e.preventDefault();
        $(this).tab("show");
    });
});


/*When clicking on Full hide fail/success boxes */
$('#name').focus(function() {
    $('#success').html('');
});
