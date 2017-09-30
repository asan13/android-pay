use strict;
use warnings;
use 5.010;

use Test::More;

use AndroidPay::Token;


my $private_key = <<KEY;
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAZyobD+MRFVlKo70sJfnRVwNIPrfN2wmXFN0KfmlaWzoAoGCCqGSM49
AwEHoUQDQgAESMGwyb2MFF/GwCnk0//5bJDN84/pplP3B4xt/9rEJsc+1vssmivT
sD418zuQf/nZH8dOlyR+nY5BK2Jggl1Z9w==
-----END EC PRIVATE KEY-----
KEY

my $enc_token = {
        tag                 => '1udPrWiMIR73O02Lg2nbMjI5IwlzVX1A65tPj5S/UrU=',
        encryptedMessage    => 'IxCBNFRCLRQxkSbmnznYa5CH0dJ0uGJZ02Bo1bepoRdq71cs6ytotT+qJj+6TQomMZec2p87Oms1vww1pa5mtQQEWBCnuMxk/U7HUPj41v/kZYh5pWD+6aRlN5LdUEov7amCo/LAUuY5P8g6LSWdYaWI9jZt07ByMzIT0iFUgHbJwLP0YhWj+g==',
        ephemeralPublicKey  => 'BPV0qRtM7tYvfTDsxwuY0doKtTbdOahSY71brl6WZy2Cr+iNnRP1iDx2CSBXpTDLS6tlHUgj3KxhWcqQqZz9pMo='
};

my $result = {
    '3dsCryptogram'     => 'ALnt+yWSJdXBACMLLWMNGgADFA==',
    'expirationMonth'   => 12,
    'authMethod'        => '3DS',
    'expirationYear'    => 2022,
    'dpan'              => '5204240250197840',
};

my $apay = new_ok('AndroidPay::Token', [$private_key]);

eval { AndroidPay::Token->new() };
ok $@, 'create without private key raises execption';

my $token = eval { $apay->decrypt($enc_token) };
is_deeply($result, $token, 'decrypt succesfull');



done_testing;





