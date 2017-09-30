use ExtUtils::MakeMaker;

WriteMakefile(
    NAME            => 'AndroidPay::Token',
    VERSION_FROM    => 'lib/AndroidPay/Token.pm',
    AUTHOR          => 'Asyakin Andrey <asan999@gmail.com>',
    PREREQ_PM       => {
        CryptX      => 0,
    },
);

