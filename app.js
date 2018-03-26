function sanitize(dirty) {
  return DOMPurify.sanitize(dirty);
}

function b64EncodeUnicode(str) {
  return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
    function toSolidBytes(match, p1) {
      return String.fromCharCode('0x' + p1);
  }));
}

function b64DecodeUnicode(str) {
  return decodeURIComponent(atob(str).split('').map(function(c) {
    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
  }).join(''));
}

function copyOwnIDKey() {
  ownIDKey.select();
  document.execCommand('copy');
}

const sleep = async (seconds) => {
  const ms = seconds * 1000;
  await (new Promise((resolve, reject) => {
    setTimeout(resolve, ms);
  }));
};

openpgp.config.compression = openpgp.enums.compression.zip;

let passphrase = [...window.crypto.getRandomValues(new Uint8Array(256))].join('');

let previouslyPressedKey = 0;

(
  async () => {

    const fname = [...window.crypto.getRandomValues(new Uint8Array(5))].map(c => String.fromCharCode(c)).join('');
    const lname = [...window.crypto.getRandomValues(new Uint8Array(10))].map(c => String.fromCharCode(c)).join('');
    const name = `${fname} ${lname}`;
    const email = `example@example.com`;

    const options = {
      userIds: [{ name, email }],
      curve: 'p521',
      passphrase: passphrase
    };

    const key = await openpgp.generateKey(options);

    const encrypt = async (data, publicKey) => {
      const options = {
        data,
        publicKeys: openpgp.key.readArmored(publicKey).keys
      };
      return (await openpgp.encrypt(options)).data;
    }

    const privKeyObj = openpgp.key.readArmored(key.privateKeyArmored).keys[0];
    await privKeyObj.decrypt(passphrase);

    const decrypt = async (encrypted, key) => {
      const options = {
        message: openpgp.message.readArmored(encrypted),
        publicKeys: openpgp.key.readArmored(key.publicKeyArmored).keys, // verify
        privateKeys: [privKeyObj]
      };
      return (await openpgp.decrypt(options)).data;
    }

    const params = (new URL(document.location)).searchParams;
    const isInitiator = params.get("init");

    if(isInitiator) {
      ownIDContainer.style.visibility = 'visible';
    } else {
      urlToInit.style.visibility = 'visible';
    }

    const p = new SimplePeer({
      initiator: isInitiator,
      reconnectTimer: 100,
      trickle: false,
      config: {
        iceServers: [
          {urls:'stun:stun.l.google.com:19302'},
          {urls:'stun:stun1.l.google.com:19302'},
          {urls:'stun:stun2.l.google.com:19302'},
          {urls:'stun:stun3.l.google.com:19302'},
          {urls:'stun:stun4.l.google.com:19302'},
          {urls:'stun:global.stun.twilio.com:3478?transport=udp'},
        ]
      }
    });

    p.on('error', function (err) { console.error('error', err) });

    p.on('signal', function (data) {
      ownIDKey.value = b64EncodeUnicode(JSON.stringify(data));
      ownIDContainer.style.visibility = 'visible';
    });

    window.connectPeer = () => {
      const peerID = JSON.parse(b64DecodeUnicode(peerIDKey.value));
      p.signal(peerID);
      urlToInit.style.visibility = 'hidden';
    }

    window.sendMessage = async () => {

      if(!window.peerPublicKey) {
        return false;
      }

      message.value = message.value.trim();

      const sanitized = sanitize(message.value).trim().replace(/\n/g, '<br>');

      messageContainer.innerHTML += `
      <div class="alert alert-secondary" role="alert">
        <div class="row">
          <div class="col-8">
            ${sanitized}
          </div>
          <div class="col-4 text-right text-muted small">
            ${(new Date()).toLocaleTimeString()}
          </div>
        </div>
      </div>
      `;
      
      messageContainer.scrollTo(0, messageContainer.scrollHeight);
      const encrypted = await encrypt(sanitized, window.peerPublicKey);
      p.send(encrypted);
      message.value = '';
    }

    p.on('connect', async function () {
      console.log('CONNECTED');
      p.send(key.publicKeyArmored);
      document.getElementsByClassName('heading-text')[0].style.color = '#17a2b8';
      document.getElementsByClassName('footer')[0].style.visibility = 'visible';
      ownIDKey.type = 'password';
      peerIDKey.type = 'password';
      document.getElementsByClassName('heading-text')[0].innerText = 'connected';
      await sleep(1);
      document.getElementsByClassName('heading-text')[0].innerText = 'chatnym';
      ownIDContainer.style.display = 'none';
      peerIDContainer.style.display = 'none';
      message.focus();
    });

    p.on('data', async function(data) {
      data = data.toString();
      if(data.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----')) {
        window.peerPublicKey = data;
        return;
      } else if(data.startsWith('-----BEGIN PGP MESSAGE-----')) {
        const decrypted = await decrypt(data, key);
        const sanitized = sanitize(decrypted).trim().replace(/\n/g, '<br>');
        messageContainer.innerHTML += `
        <div class="alert alert-info" role="alert">
          <div class="row">
            <div class="col-8">
              ${sanitized}
            </div>
            <div class="col-4 text-right text-muted small">
              ${(new Date()).toLocaleTimeString()}
            </div>
          </div>
        </div>
        `;
        messageContainer.scrollTo(0, messageContainer.scrollHeight);
      } else {
        throw new Error('Unencrypted Message Sent! Message Text: ' + data.toString());
      }
    });

    message.addEventListener('keydown', async (event) => {
      event.which = event.which || event.keyCode;
      if(event.which === 13 && event.shiftKey === false) {
        event.preventDefault();
        await window.sendMessage();
        return false;
      }
    });

  }
)()
.catch(err => {
  console.error(`Something went wrong! Here is what happened: ${err}`);
});