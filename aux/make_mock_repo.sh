#!/bin/sh

# This script requires a working CernVM-FS Server installation and creates the
# mock repository used in the python unit tests.

set -e

die() {
  echo $1 >&2
  exit 1
}

[ $(id -u) -eq 0 ] || die "need root for this script"

REPO_NAME="test.cern.ch"
KEYS_DIR="/etc/cvmfs/keys"
REPO_DIR="/cvmfs/${REPO_NAME}"
REPO_STORAGE="/srv/cvmfs/${REPO_NAME}"

cvmfs_server list | grep -q $REPO_NAME && die "$REPO_NAME already exists"

echo -n "recreating keychain... "
cat >> ${KEYS_DIR}/${REPO_NAME}.pub << EOF
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAueS/yBwR4UlRsgkv7hcM
ljvt/KyrhkI5y7n7ksLBFumjPhieaWz3L44s4Y1dUJ2H8krRqLXVjQ0X5x/F/nCH
erxxjuei4Vu9yG6BFqow0ZdmjqJzU4swRylBkSjf4QVOVSxUcbd7sL2QVbRH9g+C
hQ42pB+PD0CcEZp3VEsFV4wI9IY7EMRUC6dwM+LG0jubvhGbvlaqtufGXDESRJEu
RM76cnfxh/0qui8Vbs93St2VhsahJWcNGdeIaXlVsMyI77u1QhztPvF39+oDWEsW
2xAkfJ5d6NZJdrmRBD3agh5Zj8DuK0VttsvXwsSMw5gwBSRGLJIB8qXf254uouuq
lQIDAQAB
-----END PUBLIC KEY-----
EOF

cat >> ${KEYS_DIR}/${REPO_NAME}.key << EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA5TQNCMPftxI8Z27ReqQKgi1MNNmfW/l0Ns1Ax2KxspBYnbE3
FBhC1/B/uzIhW8mrYcXlFQ0400WfJHC+/pquDR/IXCrWB+1dyz9dp/7l4HcxcDNH
fc/g2hSvtdcw1ZCHNGONcCOxOYE3Rx10eZjviQZiGkzVkHwpnjgWNxbT7bkIV6iu
R8YWNUfGABwhTB5diq3UPtw5LEwYYj/CKFR9BkTK0VmZJbXV5bAvGQyINfT5296r
XJWD4WItJJ95R/zkBQgBjvLTNpFPRiOln8FTFpEDVWdteezDDXGWNWma3jYwvJg8
PBZEEcUmZBDQT9k0nfRizhsTyO7xzDmcAPfVHQIDAQABAoIBAB1JV1kFXjKQO/Oj
b1TSXR1hGFmwbPJdn4HZHCvd6oK8evY7TKRerTvWWRvcPfLyg9mMZccY12f3f2wy
k9UIgrDenMVaG9sLc26i/B6ZLVpPIJwLkVj8FOkIt6LuiijfvMbu6YWoqd6FKkEF
/HoFFqZVkHd31doOY2r6E6yaWB4JxqXcNJLAQRnm0mCytZUkzHodr+Tsy1GkSJC2
I3saPSIG5u4TL3XVsIBs5mE47FLK/YKRHJyp3tTLgTkhDvpLPEJC8ij1oWJ4PSzo
jeaK8xpv+LAjqu8brL9WZQI812Fmx+nPncSmKZrmjAYr4HaZ4aAgsWKOnqnyzrZv
QSao9EECgYEA8p1g/4iZVXkUjNVL6a+Cmj+g6+ji9wPXDOXFiwlOgXCDRFxunaMM
ZbZtxe26XHQdVm4e2hC4Zv2nn7Sn9gGg+7NCso5Y5qDH2HMJ/w+ya6XUIcE/YDMb
PqK6llLqsyLg+nrtV0ZkA5UN8Rlp116fWE0ensszH9qF43pB+7m8ANkCgYEA8dlA
sv9ZJW4/MtK8dbxzmrpyCRbLFsuYYN7k1ybrUVvK6WpGljqKbduTJ3/XC6qhJuWR
YAH9aTwwvRvEJor0EnYc+QpEnv5KHfNkKFU2x3tnnYZT24t2PLpY9AECjgeSUDk+
kHQzUGmig5eSSYMpGdLvRtD0BYXQLoD8eAy3y+UCgYEAtQ0jFK7Qlotr/YkzRGm4
kfmH0mUR8vqHolVZ7N7+GfRn0T0VQ0go+UKBeuJkX5g7SIOXPG6b3ifOzozXhutC
QnNNA8jcqQc0+98lh5UkNdcjjikTbWvWGhEAIywvf404zVOtCKM8AbxbEiA/7vvq
989dWW0UcuH1ZoOW+A5sMUkCgYB/E+zPISUyac+DYP/tzWvhLX6mD/f+rlQO8o/E
DYswYM8p/tHANlpuhyW3Z5ETbEDpM09D50fEeAAUHfbfWbwNx0pKAX81G+DOBAno
t33lK46yUtbVUV57Yl9DNxSklI3o4Wtic+xSoG7oPkh7oBOEojVgPIM8M6fEB7qh
Se15kQKBgBQ8/Z4A95yoGlv1RYOBuZpOpEtbgi/NiJdRXnzrmQ1m31heRbkfu3w0
5WzlYjaQQ3g3rsh+0Ond9bLFcZor6azcPSsu+cjC3Gsxm/0KZKPAroi73Gd4O0QH
ih/vJDlTHRS2ArfdYc9cUYTFvs8YuLy7y9Uho35ey6PLX6CEsJel
-----END RSA PRIVATE KEY-----
EOF

cat >> ${KEYS_DIR}/${REPO_NAME}.crt << EOF
-----BEGIN CERTIFICATE-----
MIIC4DCCAcgCCQCXrInX5ZovjjANBgkqhkiG9w0BAQUFADAyMTAwLgYDVQQDDCd0
ZXN0LmNlcm4uY2ggQ2VyblZNLUZTIFJlbGVhc2UgTWFuYWdlcnMwHhcNMTUwNjEx
MTMyOTEzWhcNMTYwNjEwMTMyOTEzWjAyMTAwLgYDVQQDDCd0ZXN0LmNlcm4uY2gg
Q2VyblZNLUZTIFJlbGVhc2UgTWFuYWdlcnMwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDlNA0Iw9+3EjxnbtF6pAqCLUw02Z9b+XQ2zUDHYrGykFidsTcU
GELX8H+7MiFbyathxeUVDTjTRZ8kcL7+mq4NH8hcKtYH7V3LP12n/uXgdzFwM0d9
z+DaFK+11zDVkIc0Y41wI7E5gTdHHXR5mO+JBmIaTNWQfCmeOBY3FtPtuQhXqK5H
xhY1R8YAHCFMHl2KrdQ+3DksTBhiP8IoVH0GRMrRWZkltdXlsC8ZDIg19Pnb3qtc
lYPhYi0kn3lH/OQFCAGO8tM2kU9GI6WfwVMWkQNVZ2157MMNcZY1aZreNjC8mDw8
FkQRxSZkENBP2TSd9GLOGxPI7vHMOZwA99UdAgMBAAEwDQYJKoZIhvcNAQEFBQAD
ggEBAEJOrTkvSCPvVRXOdV1mnK4tdD2DtVkrKbYdvhuu66lTcyBrtwA3Dz/gNXZ7
6M42mQ7KFKaeXK+saO1A9wc4ENl5owQXZRZTDdzR5Po4Dp7dXBIWXcpn8wYdcYiU
hVJ9jO4vH7rL6J2Bvpo7G1nbhdXQF848so9D6cGp2YwVlFpZhaAx5w6eUh8nHIWo
UgrhwvvQlbfny+s3UWATnop8HnoS7soMd8tcITTTwqCVQTfd9uMOmpKtYOneT1ih
PV47/c5rmF9eV1IJgnAkKocDZTEV8z/kr36FFtDSMDFcKkTSIUN+NTDMyp2pHsLG
JvkBWdL6kHjJ2kF3nD6Smtmuemg=
-----END CERTIFICATE-----
EOF

cat >> ${KEYS_DIR}/${REPO_NAME}.masterkey << EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAueS/yBwR4UlRsgkv7hcMljvt/KyrhkI5y7n7ksLBFumjPhie
aWz3L44s4Y1dUJ2H8krRqLXVjQ0X5x/F/nCHerxxjuei4Vu9yG6BFqow0ZdmjqJz
U4swRylBkSjf4QVOVSxUcbd7sL2QVbRH9g+ChQ42pB+PD0CcEZp3VEsFV4wI9IY7
EMRUC6dwM+LG0jubvhGbvlaqtufGXDESRJEuRM76cnfxh/0qui8Vbs93St2Vhsah
JWcNGdeIaXlVsMyI77u1QhztPvF39+oDWEsW2xAkfJ5d6NZJdrmRBD3agh5Zj8Du
K0VttsvXwsSMw5gwBSRGLJIB8qXf254uouuqlQIDAQABAoIBAASWKUk1sBc/6N0c
rusP9IaMaf3PANhqL+Tf7N4dIgh/sUBp+Rae0qaAuojCJShFCsKmp++itOcrCIjy
Vr9FZYJYvfCJtJIc4lzcpSC7CENTmfsw9Ol9yK4ozW5YdNWnfNxLILZBkbK1qqcC
sLfYgB7qT9zSzoPQ00j357PTugkD56eiJcNZu80nRy0Ud3D/3dDFJADF1hQkebwu
82NLqNQnTO2/KF1fJLgsIU3ymMdOV68k9rjtGfLRoK4qfX0lb8BNrAY2urPzU0yV
Y2unrWWbmWT2lDOIqRCfLbGSQuVfLbY7JOq+PwA+H7C2Py6GQLuFi8t5DTVuGke/
NtZpHkECgYEA9u+OPbZLISvmGNFZg4hn6k8PfH0GLrEcx0tPv4ReONqwXVobeYKX
/x0b6o2BC0bmICMjnGsDrZSZj2wiXAYknSQCxMAGAj0PoBI9KQNU1Simwb/IA0EE
d+c6BdR0YdVIQ7esSNaCaAb0zX1/y98U7HOQ2/ornhAM4wKKRtwykMUCgYEAwLeV
IvRHnwXls8kux+KOEAHGoWf4KqaOYUbqktSdVB5DziqN2Ktj46/wQxcmaS5gbMNR
B+lvveP7t3qKzMMMeBtKEKou1lGC+K7yWo//v1st25p8j9Ue0xlaw5ZiVRyYzZYV
uwnaBNFiNk8YH+to8UdwYGDPuNNZjE7JuFcdr5ECgYEAtsTKWBzj8LJoRXg2M+ez
WjaYNMDo4YhPz6aLaSpU/unGXeICseYaEEYAUpPXrnwUejbn9a8zcrepDQGxUMFv
OivcLLof+GovdX/qar+/e2HyQzdqmBX4c7LePFBqr7rIGO8KgoLa1JpJeQrpmwEL
oJNM5bR9sikZELDhnd7/Qi0CgYAV8VEzx6iX/K3oyJFhBPSz8d/R5OqmwIwZm19+
FGNNfpytzr6T2v/mntO2b95Zv4QPHjYNtpCYiGrSu0sugU7cJg9K0nW+xU0qT5Ec
qqSt/w27oV1paxS1aH+jIW5Uzoq/bcVPpJGEVurd0CepCr7KKh4rexprqvTZOudQ
6+pfYQKBgBmC5quiKh2ILLh5IJ1g5UXQPzFgE6J9XcVY3BumXBr41g2CYPC5oklM
v5PZ3wY76x8O+2S+sYBKzDHOv3Q8AJPC2PEIJORzTK6XfIetpnN3TR0LZvHiUpES
hmCojC2QE3Y7i+XTL2d9rbXLSIbMEWDHdBHKzTWczDIDo+tFPEFo
-----END RSA PRIVATE KEY-----
EOF
echo "done"


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


echo "creating repository ($REPO_NAME)..."
cvmfs_server mkfs -o $(id -un) $REPO_NAME


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


echo "creating revision 2 ..."
cvmfs_server transaction $REPO_NAME

rm -f    ${REPO_DIR}/new_repository

mkdir -p ${REPO_DIR}/foo
touch    ${REPO_DIR}/foo/.cvmfscatalog

mkdir -p             ${REPO_DIR}/bar
mkdir -p             ${REPO_DIR}/bar/1
mkdir -p             ${REPO_DIR}/bar/2
mkdir -p             ${REPO_DIR}/bar/3
mkdir -p             ${REPO_DIR}/bar/4
echo "René Meusel" > ${REPO_DIR}/bar/author
echo "hello world" > ${REPO_DIR}/bar/hello_world
dd if=/dev/zero   of=${REPO_DIR}/bar/big bs=1024 count=20480

cvmfs_server publish $REPO_NAME


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


echo "creating revision 3 ..."
cvmfs_server transaction $REPO_NAME

echo "/bar/*" > ${REPO_DIR}/.cvmfsdirtab

echo "foo" > ${REPO_DIR}/bar/1/foo
echo "foo" > ${REPO_DIR}/bar/2/foo
echo "foo" > ${REPO_DIR}/bar/4/foo

mkdir -p ${REPO_DIR}/bar/3/1
mkdir -p ${REPO_DIR}/bar/3/2
mkdir -p ${REPO_DIR}/bar/3/3

echo "bar" > ${REPO_DIR}/bar/3/1/bar
echo "bar" > ${REPO_DIR}/bar/3/2/bar
echo "bar" > ${REPO_DIR}/bar/3/3/bar

cvmfs_server publish $REPO_NAME


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


echo "updating repository information..."
JSON_FILE="$(mktemp)"
cat >> $JSON_FILE << EOF
{
  "administrator" : "Rene Meusel",
  "email"         : "dont.send.me.spam@cern.ch",
  "organisation"  : "CERN",
  "description"   : "This is a test repository",
  "recommended-stratum1s" : [
    "http://cvmfs-stratum-one.cern.ch/cvmfs/test.cern.ch",
    "http://cernvmfs.gridpp.rl.ac.uk/cvmfs/test.cern.ch",
    "http://cvmfs.racf.bnl.gov/cvmfs/test.cern.ch"
  ],

  "custom" : {
    "foo" : "This is",
    "bar" : "arbitrary data"
  }
}
EOF

cvmfs_server update-repoinfo -f $JSON_FILE $REPO_NAME
rm -f $JSON_FILE


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


echo "packaging up the created repository... "
TMP_DIR="$(mktemp -d)"
TMP_DIR_CVMFS="${TMP_DIR}/cvmfs"
mkdir -p $TMP_DIR_CVMFS
cp -R $REPO_STORAGE $TMP_DIR_CVMFS

echo ""
echo "use this directly in mock_repository.py:"
echo ""
echo "    repo_data = '\\\\n'.join(["

LAST_CWD=$(pwd)
cd $TMP_DIR
tar -zc . | base64 | sed -e "s/^\(.*\)\$/'\1',/g"
cd $LAST_CWD

echo "''"
echo "        ])"
echo ""

rm -fR $TMP_DIR


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


echo "removing the CernVM-FS mock repository..."
cvmfs_server rmfs -f $REPO_NAME
