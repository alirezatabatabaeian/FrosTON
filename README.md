# FrosTON
This project implements creating and verifying threshold signatures using FROST protocol on TON. In this repository key generation ceremony and signing is discussed which can be tested in `frost_exec.py`. The script outputs integers that can be used in FunC to verify correctness. The contracts are available at [FrosTON-Contracts](https://github.com/alirezatabatabaeian/FrosTON-contracts).

Update (2h after deadline): To provide a more clear information on the protocol and steps, a new [Report](https://github.com/alirezatabatabaeian/FrosTON/blob/main/FrosTON-report.pdf) is added to the project for easier evaluation.
## Building
First clone the repo.

```
git clone https://github.com/alirezatabatabaeian/FrosTON
cd FrosTON
git clone https://github.com/alirezatabatabaeian/frost-dalek
```


We recommend to use `maturin` in a `venv` to compile the bindings. Installing `maturin` can be done by running:

```
python3 -m venv .env
source .env/bin/activate
pip install maturin
```

Compiling the bindings can be done as follows:

```
maturin develop
```

## Running

Simply run `frost_exec.py`.

```
> python frost_exec.py
Group Key is verified and Ready
A = 7630892626073697179649892243312127891887158125846685435027972819102567337757;
Message Hash Ready
H1 = 42591119791994701449560837725353037344160559634474477656402079052005071383338;
H2 = 105459063227580780287661165349844655550145830334741275685808294282746092285676;
Schnorr Threshold Signature is Ready
R = 112449329612809383475655916300027265220974827965209180369834572115136917021562;
Z = 55593887614118773236222527059555867928447886529784854303787195680455687643661;
Checking signature to ensure correctness
Signature valid :)
```

## References
We used [frost-python](https://github.com/devos50/frost-python) bindings to construct this project which uses our [custom fork of frost](https://github.com/alirezatabatabaeian/frost-dalek).
