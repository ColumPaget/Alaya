#include "../libUseful.h"

void main()
{
PasswordFileAdd("/tmp/test.pw", "sha1", "test user", "testing 123", "a test user\nmaybe\n");
PasswordFileAdd("/tmp/test.pw", "sha1", "another", "another password", NULL);
PasswordFileAdd("/tmp/test.pw", "plain", "bad:cred", "password with 'bad:creds'\n", NULL);
PasswordFileAdd("/tmp/test.pw", "sha256", "bad:username", "another password", "bad:username\nand some bad extra");

printf("CHECK1: (sha1): %d\n", PasswordFileCheck("/tmp/test.pw", "test user", "testing 123", NULL));
printf("CHECK2: ('another' sha1) %d\n", PasswordFileCheck("/tmp/test.pw", "another", "another password", NULL));

PasswordFileAdd("/tmp/test.pw", "whirl", "another", "another password", NULL);

printf("CHECK3: ('another' whirl) %d\n", PasswordFileCheck("/tmp/test.pw", "another", "another password", NULL));
printf("CHECK4: ('bad:username') %d\n", PasswordFileCheck("/tmp/test.pw", "bad:username", "another password", NULL));
printf("CHECK5: ('bad:cred') %d\n", PasswordFileCheck("/tmp/test.pw", "bad:cred", "password with 'bad:creds'\n", NULL));
printf("CHECK6: ('test user, wrong password') %d\n", PasswordFileCheck("/tmp/test.pw", "test user", "testing 456", NULL));
printf("CHECK7: ('nonexistent user') %d\n", PasswordFileCheck("/tmp/test.pw", "test noexist", "testing 123", NULL));


}
