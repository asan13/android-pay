package AndroidPay::Token;
use strict;
use warnings;
use 5.010;

our $VERSION = '0.01';

=encoding utf8

=head1 Token

Рефлизация алгоритма расшифровки платежного токена, описанная здесь: 
https://developers.google.com/android-pay/integration/payment-token-cryptography#decrypting-the-payment-token

=cut


use JSON::XS;
use MIME::Base64;

use Crypt::PK::ECC ();
use Crypt::KeyDerivation ();
use Crypt::Mac::HMAC;
use Crypt::Mode::CTR;

sub new {
    my $class = shift;
    my $pkey  = shift or die 'private key required';

    bless {private_key => $pkey}, $class;
}

sub decrypt {
    my ($self, $token) = @_;

    for ( qw/ephemeralPublicKey encryptedMessage tag/ ) {
        $token->{$_} or die "invalid token format: '$_' required";
    }

    my $eph_key = decode_base64 $token->{ephemeralPublicKey};
    my $enc_msg = decode_base64 $token->{encryptedMessage};
    my $tag     = decode_base64 $token->{tag};


    my $shared = $self->_shared_key($eph_key);


    my $hkdf = Crypt::KeyDerivation::hkdf( $eph_key . $shared, 
        "\0"x32, 
        'SHA256', 
        32, 
        'Android',
    );


    my $symmetric_key = substr $hkdf, 0, 16;
    my $mac           = substr $hkdf, 16, 32;


    my $compute_tag = Crypt::Mac::HMAC::hmac('SHA256', $mac, $enc_msg);


    unless ($self->_verify_tag($compute_tag, $tag)) {
        die 'tag verification failed';
    }

    my $msg = $self->_decrypt($symmetric_key, $enc_msg);

    decode_json $msg;
}   

sub _verify_tag {
    my ($self, $tag, $tag2) = @_;

    return 0 unless length $tag == length $tag2;

    my $res = 0;

    for (map unpack('C'), split //, $tag) {
        $res |= $_ ^ unpack 'C', substr $tag2, 0, 1, '';
    }

    return $res == 0 ? 1 : 0;
}

sub _decrypt {
    my ($self, $key, $enc_msg) = @_;

    state $aes = Crypt::Mode::CTR->new('AES', 
        1,      # 0 - little-endian, 1 - big-endian 
        128
    );

    state $iv = "\0"x16;

    $aes->start_decrypt($key, $iv);

    my $text = $aes->add($enc_msg) . $aes->finish;

    return $text;
}

sub _shared_key {
    my ($self, $eph_key) = @_;

    my $point = substr $eph_key, 1;
    my $ecc_public = {
        pub_x      => join('', unpack 'H*', substr($point, 0, 32)),
        pub_y      => join('', unpack 'H*', substr($point, 32, 32)),
        curve_name => 'nistp256',
    };

    return Crypt::PK::ECC::ecc_shared_secret(
        Crypt::PK::ECC->new( \$self->{private_key} ),
        Crypt::PK::ECC->new( $ecc_public ) 
    );
}


1;
