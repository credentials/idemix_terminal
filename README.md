# Idemix terminal

This library provides a terminal implementation to bridge between the cryptographic IRMA library  
[credentials_idemix](https://github.com/credentials/credentials_idemix) and an IRMA smart card. In essense it translates high level protocol messages into messages the smart card can understand (APDUs).

There are basically two modes of operation. The first mode uses a SCUBA CardService to interact
directly with the smart card. The second mode is used for asynchronous or indirect communication with the card. Hence the library only constructs the protocol commands to be send to the card, whereas the developer is responsible for performing the actual communication with the card.

The Idemix Terminal makes it easy to issue and verify credentials that are described in credentials/irma_configuration. We introduce this using a couple of examples. For all these examples we assume that you obtained a `CardService` to talk to the card. You could for example use:

```Java
CardService cs = new TerminalCardService(
    TerminalFactory.getDefault().terminals().list().get(0));
```

to connect to a cardreader. Alternatively, you can use a simulated card, see `TestSetup#getCardService()` for an example. Next, we setup the system so that it can actually load and use the irma_configuration settings. In particular we run:

```Java
URI core = new File(System.getProperty("user.dir")).toURI().resolve("irma_configuration/");
DescriptionStore.setCoreLocation(core);
IdemixKeyStore.setCoreLocation(core);
```

After setting up you can run:

```Java
IdemixVerificationDescription vd = new IdemixVerificationDescription(
    "Surfnet", "rootNone");
Attributes attr = new IdemixCredentials(cs).verify(vd);
```

to verify the Surfnet root credential, while keeping all attributes hidden. The description of this verfication can be found in `irma_configuration/Surfnet/Verifies/rootNone/`. When the credential verified, `attr` contains the revealed attributes (possibly represented by an empty list), otherwise `attr` is `null`. Similarly, a Surfnet root credential can be issued as follows: 

```Java
// Retrieve the issue specification and get the Issuer's private key
CredentialDescription cd = DescriptionStore.getInstance().
    getCredentialDescriptionByName(issuer, credential);
IdemixSecretKey isk = IdemixKeyStore.getInstance().getSecretKey(cd)

// Setup the attributes that will be issued to the card
Attributes attributes = new Attributes();
attributes.add("userID", "s1234567@student.ru.nl".getBytes());
attributes.add("securityHash", "DEADBEEF".getBytes());

// Setup a connection and send pin
IdemixService is = new IdemixService(cs);
IdemixCredentials ic = new IdemixCredentials(is);
ic.connect();
is.sendPin({0x30, 0x30, 0x30, 0x30}); // TODO: Change to send the correct pin.

// Issue the credential
ic.issue(cd, isk, attributes, null); // null indicates default expiry
```

### Asynchronous use

In some scenario's (like when using a web server) you don't have direct access to a card reader. The API offers a lower-level asynchronous access point, where you get the APDU that need to be send to the smart card, and can handle them in any way that you like.

First, we select the credential as before

```Java
IdemixVerificationDescription vd = new IdemixVerificationDescription(
    "Surfnet", "rootNone");
IdemixCredentials ic = new IdemixCredentials(null);
```

To keep this example simple, we use the regular `IdemixService` to send the commands to the card. Replace this with whatever suits your application best.

```Java
// Open channel to card
IdemixService service = new IdemixService(cs);
service.open();
```

First, we select the applet and process the resulting version number.

```Java
ProtocolResponse select_response = service.execute(
IdemixSmartcard.selectApplicationCommand);
CardVersion cv = new CardVersion(select_response.getData());
```

To verify a credential the verifier generates a nonce, before it generates the commands to send to the card. This nonce is also necessary to verify the responses. We'll want to store this nonce, for when the responses come in.

```Java
BigInteger nonce = vd.generateNonce();
```

Next, we generate the actual verification commands, and send them to the card.

```Java
ProtocolCommands commands = ic.requestProofCommands(vd, nonce);
ProtocolResponses responses = service.execute(commands);
```
                
Finally, we verify the attributes. Here we use the nonce that we generated earlier.

```Java
Attributes attr = ic.verifyProofResponses(vd, nonce, responses);
```

## Prerequisites

This library has the following dependencies.  All these dependencies will be automatically downloaded by gradle when building or installing the library (except for cert-cvc which is included).

Internal dependencies:

 * [credentials/credentials_idemix](https://github.com/credentials/credentials_idemix) The IRMA Idemix implementation
 * [credentials/scuba](https://github.com/credentials/scuba/), scuba_smartcards The Scuba smart-card abstraction layer

External dependencies:

 * [Google GSON](https://code.google.com/p/google-gson/)

For running the tests:

 * JUnit,  (>= 4.8), the Java unit-testing library
 * [credentials/scuba](https://github.com/credentials/scuba/), scuba_sc_j2se
 * [EJBCA](http://www.ejbca.org/), Cert-CVC (already included in `lib`)

## Building using Gradle (recommended)

When you are using the Gradle build system, just run

    gradle install

to install the library to your local repository. Alternatively, you can run

    gradle build

to just build the library.

## Eclipse development files

You can run

    gradle eclipse

to create the required files for importing the project into Eclipse.

## Using the library

Before using the library you need to setup `irma_configuration`.

### irma_configuration

Download or link the `irma_configuration` project to a location within your tree. In particular the tests below assume that `irma_configuration` is placed in the root of this project.

See the credentials/irma_configuration project for the specifics. Remember that you can check out a different branch to get a different set of credentials and corresponding keys. In particular, the demo branch contains keys for all the issuers as well, thus making it very easy to test and develop applications.

## Issueing/Verifying/Deleting credentials

You can use gradle to quickly get some credentials on your card. This assumes that you have linked/checked `irma_configuration` in the root of this project (and have the necessary keys for issuing, for example by using the demo branch).

    gradle test --tests "*issue*"

You can use the tests to verify the same credentials or remove them

    gradle test --tests "*verify*"
    gradle test --tests "*remove*"

You can use this format to specify any tests. For example you can just issue yourself a root credential:

    gradle test --tests "*issueRootCredential"

If you desire more verbose output, you can also decide to pass the `-Pverbose` flag to see all the output generated by the tests.

    gradle -Pverbose test --tests "*verifyRootCredentialAll"
