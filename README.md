# encryption-tool

``` 
整合了大部分常用的加密/解密工具的框架，方便根据特定使用场景方便的使用合适的加密/解密算法，
并对大部分异常进行了解释说明，方便使用者快速定位问题。
```

## 项目链接
[encryption-tools](https://github.com/wuyue930912/encryption-tools)

## 常用的加密/解密算法介绍及其常用的应用场景

### BCrypt

```
BCrypt是一种密码哈希函数和密码学算法，用于对密码进行安全存储和验证。它使用Salt（盐）和适应性哈希函数的组合，以提供更高的安全性。

BCrypt的主要特点和工作原理如下：

    1. 盐（Salt）：盐是一个随机生成的字符串，它与密码一起输入哈希函数，增加了密码的复杂性和安全性。每个密码都使用不同的盐进行加密，即使密码相同，生成的哈希值也会不同。
    
    2. 适应性哈希函数：BCrypt使用适应性哈希函数，它会根据工作因子（work factor）进行多次迭代，以增加计算成本。工作因子决定了哈希函数的计算时间和资源消耗，可以通过增加工作因子的大小来提高哈希函数的安全性。
    
    3. 哈希函数输出：BCrypt生成的哈希值包括了盐和密码的组合，并且具有固定的长度。哈希值可以用于存储在数据库中，以便后续验证密码时进行比较。

常见的使用场景包括：

    1. 用户密码存储：BCrypt广泛用于存储用户密码。当用户注册或更改密码时，将其密码使用BCrypt进行哈希处理，并将哈希值存储在数据库中。在验证用户登录时，将用户输入的密码与存储的哈希值进行比较，以验证密码的正确性。
    
    2. 认证和授权系统：BCrypt可用于构建认证和授权系统，以保护敏感资源和数据。用户的密码可以使用BCrypt进行哈希处理，并与存储的哈希值进行比较，从而实现用户身份验证。
    
    3. 安全敏感操作的密码验证：BCrypt适用于对一些安全敏感操作进行密码验证，例如访问管理后台、修改重要设置等。通过使用BCrypt验证密码，可以增加操作的安全性，防止未经授权的访问。

总的来说，BCrypt是一种可靠且广泛使用的密码哈希函数和密码学算法，用于存储和验证密码。它提供了安全性和可扩展性，并在许多应用场景中用于保护用户密码和敏感数据。
 ```

### AES

 ```
AES（Advanced Encryption Standard）是一种对称加密算法，被广泛应用于数据保护和安全通信领域。它是目前最常用的加密算法之一。

AES的主要特点和工作原理如下：

      1. 对称加密：AES是一种对称加密算法，意味着相同的密钥用于加密和解密数据。发送方使用密钥对数据进行加密，接收方使用相同的密钥对数据进行解密。
      
      2. 块加密算法：AES以块为单位对数据进行加密，每个块的大小为128位（16字节）。数据长度不足一个块的倍数时，会使用填充方式进行处理。
      
      3. 密钥长度：AES支持128位、192位和256位的密钥长度，密钥长度越长，加密强度越高。
      
      4. 轮（Round）和子密钥生成：AES使用多轮加密过程，每轮包括字节替代、行移位、列混淆和轮密钥加。这些操作通过迭代应用于数据块，以增加加密的复杂性和安全性。
  
常见的使用场景包括：

      1. 数据加密和保护：AES被广泛用于保护敏感数据的安全性，例如在存储或传输过程中对数据进行加密。它可以用于加密文件、数据库记录、通信协议等，以确保数据在传输和储存过程中不被未经授权的访问者所读取或篡改。
      
      2. 网络通信安全：AES被用于加密网络通信，例如在HTTPS中用于加密传输层安全性（TLS）协议。它可以保护敏感信息（如用户凭据、信用卡信息）在客户端和服务器之间的传输过程中的机密性和完整性。
      
      3. 文件和文件夹加密：AES可以用于加密整个文件或文件夹，以确保文件在存储或传输过程中的安全性。这种加密方式可以用于保护个人文件、敏感文档等。
      
      4. 数据库加密：AES可以用于对数据库中的数据进行加密，以提高数据库的安全性。通过对敏感数据进行加密，即使数据库被未经授权的访问者获取，也无法读取其中的明文数据。

总的来说，AES是一种强大且广泛应用的对称加密算法，被用于保护数据的机密性和完整性。它可以在各种场景中使用，包括数据加密、网络通信安全、文件加密和数据库加密等。
 ```

### RSA

 ```
RSA（Rivest-Shamir-Adleman）是一种非对称加密算法，广泛用于数据加密、数字签名和密钥交换等领域。它是目前最常用的非对称加密算法之一。

RSA的主要特点和工作原理如下：

      1. 非对称加密：RSA使用一对密钥，包括公钥和私钥。公钥用于加密数据，私钥用于解密数据。由于公钥和私钥是不同的，所以称为非对称加密算法。
      
      2. 密钥生成：RSA的密钥由两个大素数生成。生成密钥时，需要选择两个大素数，并计算出与之相关的公钥和私钥。
      
      3. 加密和解密：使用公钥对数据进行加密，只有使用相应的私钥才能解密。加密后的数据只能通过私钥进行解密，以确保数据的机密性。
      
      4. 数字签名：RSA还可以用于生成和验证数字签名。私钥用于生成数字签名，公钥用于验证签名。数字签名可用于验证数据的完整性和身份认证。

常见的使用场景包括：

      1. 数据加密和保护：RSA被广泛用于对敏感数据进行加密和保护。例如，可以使用RSA加密算法对用户的登录凭据、支付信息等进行加密，以确保数据在传输和储存过程中的安全性。
      
      2. 数字签名和身份认证：RSA可用于生成和验证数字签名，以保证数据的完整性和身份认证。数字签名可以用于验证数据的来源和确保数据在传输过程中未被篡改。
      
      3. 密钥交换：RSA也可以用于密钥交换，例如在安全通信中使用。发送方可以使用接收方的公钥加密会话密钥，然后将密文发送给接收方。接收方使用其私钥解密密文以获得会话密钥，从而实现安全的密钥交换。
      
      4. SSL/TLS通信：RSA在SSL/TLS协议中扮演重要的角色。它用于在客户端和服务器之间建立安全的通信连接，包括密钥交换、身份认证和通信数据的加密。

总的来说，RSA是一种强大且广泛应用的非对称加密算法，用于数据加密、数字签名和密钥交换等领域。它提供了数据的机密性、完整性和身份认证，被广泛用于保护敏感信息和确保通信的安全性。
 ```

### ECC

 ```
ECC（Elliptic Curve Cryptography）是一种基于椭圆曲线的非对称加密算法。它与RSA和DSA等传统加密算法相比，在相同的安全性水平下，具有更短的密钥长度和更高的计算效率，因此在资源受限的环境下更加适用。

ECC的主要特点和工作原理如下：

      1. 椭圆曲线：ECC基于椭圆曲线上的离散数学问题，利用椭圆曲线的数学特性进行加密和解密操作。椭圆曲线方程形式为 y^2 = x^3 + ax + b，在有限域上进行计算。
      
      2. 密钥生成：ECC使用椭圆曲线上的点作为公钥，私钥是一个随机数。通过选择合适的椭圆曲线和生成私钥，可以计算出对应的公钥。
      
      3. 加密和解密：使用对方的公钥对数据进行加密，只有持有相应私钥的一方才能解密。加密和解密过程涉及椭圆曲线上的点运算和数论运算。
      
      4. 密钥长度：相比于传统加密算法，ECC可以使用更短的密钥长度达到相同的安全性水平。这对于资源受限的设备和网络通信中的性能优化非常有利。

常见的使用场景包括：

      1. 移动设备和物联网（IoT）：由于ECC可以使用较短的密钥长度，适用于资源受限的移动设备和物联网设备。它可以用于保护移动设备上的敏感数据和通信，以及在物联网中确保设备之间的安全通信。
      
      2. 数字证书和SSL/TLS通信：ECC广泛应用于数字证书和SSL/TLS通信领域。它可以用于生成和验证数字证书，以及在客户端和服务器之间建立安全的通信连接，提供身份认证、密钥交换和通信数据的加密。
      
      3. 加密协议和安全通信：ECC可用于构建安全通信协议，例如加密电子邮件、加密即时通信和虚拟专用网络（VPN）。它可以提供机密性、完整性和身份认证，确保通信的安全性。
      
      4. 区块链和加密货币：ECC在区块链技术和加密货币中扮演重要角色。它用于生成和验证数字签名，确保交易的有效性和安全性。

总的来说，ECC是一种高效且安全的非对称加密算法，适用于资源受限的环境和性能敏感的应用。它广泛应用于移动设备、物联网、SSL/TLS通信、加密协议、区块链和加密货币等领域，提供数据的保护和安全通信的支持。
 ```

### SHA-1

 ```
SHA-1（Secure Hash Algorithm 1）是一种哈希函数，用于将任意长度的数据转换为固定长度（160位）的哈希值。它是SHA系列算法中的一员，由美国国家安全局（NSA）于1995年发布。

SHA-1广泛应用于许多领域，包括密码学、数据完整性校验和数字签名等。以下是一些常见的使用场景：

      1. 数据完整性校验：SHA-1可用于校验数据的完整性，确保数据在传输或存储过程中没有被篡改。发送方可以对发送的数据计算SHA-1哈希值，并将其一同发送给接收方。接收方可以再次计算SHA-1哈希值，并与接收到的哈希值进行比较，以验证数据的完整性。
      
      2. 数字签名：SHA-1常用于生成数字签名。在数字签名过程中，使用私钥对数据的SHA-1哈希值进行加密，生成数字签名。接收方可以使用相应的公钥对数字签名进行解密，并计算数据的SHA-1哈希值，然后将两者进行比较，以验证签名的真实性和数据的完整性。
      
      3. 安全协议：SHA-1在一些安全协议中起到重要作用，例如SSL/TLS（Secure Sockets Layer/Transport Layer Security）协议中的证书验证过程。在该过程中，服务器使用SHA-1对其证书的公钥进行哈希运算，以提供给客户端进行验证。

然而，需要注意的是，SHA-1算法已经不再被认为是足够安全，因为它存在一些安全性漏洞和碰撞攻击的风险。因此，在现代的应用中，推荐使用更强大和安全性更高的哈希算法，如SHA-256、SHA-512等。
 ```

### SHA-256

 ```
SHA-256（Secure Hash Algorithm 256-bit）是SHA-2系列算法中的一种，是一种密码学安全哈希函数。它将任意长度的数据转换为固定长度的哈希值（256位），具有较高的安全性和抗碰撞性。

以下是SHA-256加密算法的介绍和常见的使用场景：

      1. 数据完整性校验：SHA-256广泛应用于数据完整性校验。通过计算数据的SHA-256哈希值，可以生成一个唯一的、固定长度的摘要。在数据传输或存储过程中，接收方可以再次计算数据的SHA-256哈希值，然后与发送方提供的哈希值进行比较，以验证数据的完整性和防止篡改。
      
      2. 数字签名：SHA-256也常用于生成数字签名。在数字签名过程中，使用私钥对数据的SHA-256哈希值进行加密，生成数字签名。接收方可以使用相应的公钥对数字签名进行解密，并计算数据的SHA-256哈希值，然后将两者进行比较，以验证签名的真实性和数据的完整性。
      
      3. 密码存储：SHA-256常用于密码存储，特别是在用户认证系统中。通常，用户的密码不会直接存储，而是将其经过SHA-256哈希处理后存储为摘要。当用户登录时，输入的密码也会经过SHA-256哈希处理，然后与存储的摘要进行比较，以验证密码的正确性。
      
      4. 区块链：SHA-256在区块链技术中发挥重要作用。区块链使用SHA-256哈希函数来生成块的哈希值，以确保每个块的完整性和链接性。此外，SHA-256还用于挖矿过程中的工作量证明（Proof of Work），以保证区块的安全性和一致性。
  
总的来说，SHA-256是一种强大且广泛使用的哈希算法，适用于数据完整性校验、数字签名、密码存储和区块链等多个领域。它提供了高度的安全性和抗碰撞性，是许多安全应用中的首选算法之一。
```

### SHA-512

 ```
SHA-512（Secure Hash Algorithm 512-bit）是SHA-2系列算法中的一种，是一种密码学安全哈希函数。它将任意长度的数据转换为固定长度的哈希值（512位），具有非常高的安全性和抗碰撞性。

以下是SHA-512加密算法的介绍和常见的使用场景：

    1. 数据完整性校验：SHA-512广泛应用于数据完整性校验。通过计算数据的SHA-512哈希值，可以生成一个唯一的、固定长度的摘要。在数据传输或存储过程中，接收方可以再次计算数据的SHA-512哈希值，然后与发送方提供的哈希值进行比较，以验证数据的完整性和防止篡改。
    
    2. 数字签名：SHA-512也常用于生成数字签名。在数字签名过程中，使用私钥对数据的SHA-512哈希值进行加密，生成数字签名。接收方可以使用相应的公钥对数字签名进行解密，并计算数据的SHA-512哈希值，然后将两者进行比较，以验证签名的真实性和数据的完整性。
    
    3. 密码存储：SHA-512常用于密码存储，特别是在安全敏感的应用中。与MD5和SHA-1相比，SHA-512提供更高的安全性和抵抗碰撞性，使得密码更难以被暴力破解。通常，用户的密码不会直接存储，而是将其经过SHA-512哈希处理后存储为摘要。
    
    4. 数据加密：SHA-512可以与其他加密算法结合使用，用于数据加密和安全通信。在加密过程中，首先对数据进行SHA-512哈希处理，然后将其作为密钥或初始向量输入到加密算法中，以增强加密的安全性。

总的来说，SHA-512是一种强大且广泛使用的哈希算法，适用于数据完整性校验、数字签名、密码存储和数据加密等多个领域。它提供了极高的安全性和抗碰撞性，是许多安全应用中的首选算法之一。然而，需要注意的是，SHA-512计算速度较慢，对于某些应用而言可能会影响性能。在选择算法时，需要综合考虑安全性和性能需求。
```

### MD5

 ```
MD5（Message Digest Algorithm 5）是一种广泛使用的哈希函数，用于将任意长度的数据转换为固定长度（128位）的哈希值。它是MD系列算法中的一员，由Ronald Rivest在1991年设计。

以下是MD5加密算法的介绍和常见的使用场景：

    1. 数据完整性校验：MD5经常用于校验数据的完整性。发送方可以对发送的数据计算MD5哈希值，并将其与接收方共享。接收方可以再次计算数据的MD5哈希值，并将其与接收到的哈希值进行比较，以验证数据在传输或存储过程中是否被篡改。
    
    2. 密码存储：在一些旧的系统中，MD5被用于存储密码的摘要。用户的密码经过MD5哈希处理后，生成一个固定长度的摘要，并将其存储在数据库中。当用户登录时，输入的密码也会经过MD5哈希处理，然后与存储的摘要进行比较，以验证密码的正确性。
    
    3. 检验文件完整性：MD5常用于检验文件的完整性。用户可以在下载文件之后，计算文件的MD5哈希值，并与提供的哈希值进行比较，以确保文件在传输过程中没有损坏或篡改。

然而，需要注意的是，MD5算法已经不再被认为是足够安全，因为它存在一些安全性漏洞和碰撞攻击的风险。因此，在现代的应用中，推荐使用更强大和安全性更高的哈希算法，如SHA-256、SHA-512等。

总的来说，MD5是一种常见的哈希算法，适用于数据完整性校验、密码存储和文件完整性检验等场景。然而，出于安全考虑，建议在重要的安全应用中使用更强大和安全性更高的哈希算法。
 ```

## 使用方法

### 1、引入依赖

 ```xml

<dependency>
    <groupId>com.may</groupId>
    <artifactId>encryption-tool</artifactId>
    <version>1.0.23</version>
</dependency>
 ```

### 2、执行命令

 ``` java
mvn install
 ```

### 3、具体用法

 ``` java
 try {
       System.err.println("--------------------------------------------------------------");
       String str = encryptionService.encryptByBCrypt("wwww");
       System.out.println("BCrypt加密后：" + str);

       Boolean matchResult = encryptionService.matchByBCrypt("wwww", str);
       System.err.println("BCrypt校验结果 : " + matchResult);

       Thread.sleep(1000);
       System.err.println("--------------------------------------------------------------");

       String key = SecretKeyUtil.generateAESKey(128);
       System.out.println("AES key : " + key);

       String cardNo = encryptionService.encryptByAES(key, "231025199909090099");
       System.out.println("AES 加密后 : " + cardNo);

       String no = encryptionService.decryptByAES(key, cardNo);
       System.err.println("AES 解密后 : " + no);

       String cardNo2 = encryptionService.encryptByAES("54321");
       System.out.println("AES 加密后 : " + cardNo2);

       String no2 = encryptionService.decryptByAES(cardNo2);
       System.err.println("AES 解密后 : " + no2);

       Thread.sleep(1000);
       System.err.println("--------------------------------------------------------------");

       RSASecretKey keys = SecretKeyUtil.generateRSAKey(512);
       System.out.println("RSA公钥字符串 : " + keys.getPublicKeyStr());
       System.out.println("RSA私钥字符串 : " + keys.getPrivateKeyStr());

       String strRsa = encryptionService.encryptByRSA(keys.getPublicKeyStr(), "who is your daddy? 一二三三二一~ 啊啊~");
       System.out.println("RSA加密后 : " + strRsa);

       String strRsaDecode = encryptionService.decryptByRSA(keys.getPrivateKeyStr(), strRsa);
       System.err.println("RSA解密后 : " + strRsaDecode);

       String strRsa2 = encryptionService.encryptByRSA("who is your mom? 一二三！三二一！啊啊！");
       System.out.println("RSA加密后 : " + strRsa2);

       String strRsaDecode2 = encryptionService.decryptByRSA(strRsa2);
       System.err.println("RSA解密后 : " + strRsaDecode2);

       Thread.sleep(1000);
       System.err.println("--------------------------------------------------------------");

       ECCSecretKey eccKeys = SecretKeyUtil.generateECCKeyPair("secp256k1");
       System.out.println("ECC公钥字符串 : " + eccKeys.getPublicKeyStr());
       System.out.println("ECC私钥字符串 : " + eccKeys.getPrivateKeyStr());

       String eccStr = encryptionService.encryptByECC(eccKeys.getPublicKeyStr(), "一朝君子一朝臣!");
       System.out.println("ECC加密后 : " + eccStr);

       String eccStr2 = encryptionService.decryptByECC(eccKeys.getPrivateKeyStr(), eccStr);
       System.err.println("ECC解密后 : " + eccStr2);

       String eccStr3 = encryptionService.encryptByECC("华语乐坛永远的神!");
       System.out.println("ECC加密后 : " + eccStr3);

       String eccStr4 = encryptionService.decryptByECC(eccStr3);
       System.err.println("ECC解密后 : " + eccStr4);

       Thread.sleep(1000);
       System.err.println("--------------------------------------------------------------");
       Thread.sleep(1000);

       String SHA1Str = encryptionService.encryptSHA1("hello呀 world!");
       System.out.println("SHA-1加密后 : " + SHA1Str);

       Boolean verResult = encryptionService.verifySHA1(SHA1Str, "hello呀 world!");
       System.err.println("SHA-1校验后 : " + verResult);

       Boolean verResult2 = encryptionService.verifySHA1(SHA1Str, "hello呀 world!！");
       System.err.println("SHA-1校验后 - 2  : " + verResult2);

       Thread.sleep(1000);
       System.err.println("--------------------------------------------------------------");

       String SHA256Str =encryptionService.encryptSHA256("hello呀 world! 256");
       System.out.println("SHA-256加密后 : " + SHA256Str);

       Boolean ver256Result = encryptionService.verifySHA256(SHA256Str, "hello呀 world! 256");
       System.err.println("SHA-256校验后 : " + ver256Result);

       String SHA512Str =encryptionService.encryptSHA512("hello呀 world! 512");
       System.out.println("SHA-512加密后 : " + SHA512Str);

       Boolean ver512Result = encryptionService.verifySHA512(SHA512Str, "hello呀 world! 512");
       System.err.println("SHA-512校验后 : " + ver512Result);

       Thread.sleep(1000);
       System.err.println("--------------------------------------------------------------");

       String MD5Str = encryptionService.encryptMD5("hello呀 world! MD5");
       System.out.println("MD5加密后 : " + MD5Str);

       Boolean verMD5Result = encryptionService.verifyMD5(MD5Str, "hello呀 world! MD5");
       System.err.println("MD5校验结果 : " + verMD5Result);

       Thread.sleep(1000);
       System.err.println("--------------------------------------------------------------");
   } catch (Exception e) {
       throw new RuntimeException(e);
   }
 ```

### 4、配置文件（应通过SecretKeyUtil生成密钥对后妥善保管、不推荐保存在配置文件中）

 ``` java
encryption:
    tool:
        #    BCrypt盐值
        BCryptSalt: $2a$10$v4ZsqFJBrfvY8LJJnowaYO
        #    AES密钥
        AESSecretKey: jb2Aw88lSbh0I4+FFycjfQ==
        #    RSA公钥
        RSAPublicKey: MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCS/GYUdEmPxNFahLCxcFoArs5pR6DJ9KiDR/8h1SewavqOwIJ6VZQg8Jf5h9Nvqj/QCfdWpUxGllisKTRcwtXbF6aeO4cf+lZVmf6MPwzk7x9d7CWZVs0XtjKpUwHEVnVRwvZ/bcdCHLEMzHRmzjEhgRKlsKzPtxU+1JoflwaxvQIDAQAB
        #    RSA私钥
        RSAPrivateKey: MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJL8ZhR0SY/E0VqEsLFwWgCuzmlHoMn0qINH/yHVJ7Bq+o7AgnpVlCDwl/mH02+qP9AJ91alTEaWWKwpNFzC1dsXpp47hx/6VlWZ/ow/DOTvH13sJZlWzRe2MqlTAcRWdVHC9n9tx0IcsQzMdGbOMSGBEqWwrM+3FT7Umh+XBrG9AgMBAAECgYADD28+qMcpT6M+O7oED79H+VvB1GR0H/xsM1EMDsiTQz7xPu/YhTSe1PONFfdggU5v0e1M6AclBxdUik0VS1cxfwIfULGsJyB/GIg8cG4XFrBpnz5w/0bfxSiN5WCSpDxk58PPH3XRQZs9A/uH8iNEar1H/Gk90XT0ENEhkEDiUQJBAMO0aDUxQzZL8MBM3cXTi0HI4ITNs4hywvO5c99UGxj2j1ZuHq8HUJl7f/TGUBuooOsEsYJOECNkP8T9HsTgsEkCQQDARXOAwZTycnprsI+sb/FPn8nryYv91+4g4GL2E4hBhay5gh0nQyOeshpzNCcU/ahD75yfdYAgQeyfwhRavd3VAkEAqrOVobASfC3JFTL2zjMy6HKaw7vYuU/AlG5Sj54A9Mk7RZxPz0OGHhoHBi5keXugwN4bJxmIIhazONPAHuINYQJACkDp6vjn35IZUzrkPpbtsIhd9VQXQh9M1LYCsQrTnmLpli8JLPnYoXLwFCq41ta8LXtOx/Y1MgMyAkcQXNJ5TQJBALFPbe92kKBiEM+pVvYgb+fi1unBeRwcYjnn0H2rkDNggBNmPJkhc7TrNkT7nvtEPiaJx80lcp0Qpqt2LYQxIE8=
        #    ECC公钥
        ECCPublicKey: MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEedCM+iL9FOgq02ZBObElh78nDkZ2gOJ94AL+1Hi9IohsPA6kDTAJ7PRhxwzEX+9+bZ+QnMwluYqldCpr5mip3Q==
        #    ECC私钥
        ECCPrivateKey: MD4CAQAwEAYHKoZIzj0CAQYFK4EEAAoEJzAlAgEBBCAdkyerWJjIre12kQqXcnydD2rB1paX/FFJPehfccdQSg==
  ```