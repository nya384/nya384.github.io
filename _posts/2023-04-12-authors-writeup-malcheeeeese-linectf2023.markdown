---
layout: post
title:  "Author's writeup: LINE CTF 2023 [CRYPTO] Malcheeeeese ( JA )"
date:   2023-04-12 00:18:00 +0900
categories: ctf crypto
---

## はじめに

こんにちは[@nya384](https://twitter.com/nya384){:target="_blank"}です。
LINE CTF 2023でCRYPTOカテゴリから`Malcheeeeese`というチャレンジを作問・出題しました。
このチャレンジは477チーム中17チームに解いていただきました。

早速ですが、作問のコンセプトについて説明しようと思います。
Base64デコーダー実装において、入力データとBase64文字列が`1:1` **ではない** issueがあります。
このようなはIssueを報告した論文[`Base64 Malleability in Practice` [CC22][1]][1]{:target="_blank"}からインスピレーションを得て作問しました。
より具体的なコンセプトは以下のとおりです。

- Base64 Oracle Attack on CTR mode + Authentication bypass using Base64 Malleability\[[CC22][1]{:target="_blank"}\]

そして、作問するにあたって参照した文献は以下のとおりです。

- \[[CC22][1]{:target="_blank"}\]: Chatzigiannis and Chalkias, Base64 Malleability in Practice
- \[[Valsorda19][2]{:target="_blank"}\]: This tweet https://twitter.com/filosottile/status/1157776085955878913

[1]:https://eprint.iacr.org/2022/361
[2]:https://twitter.com/filosottile/status/1157776085955878913

### Short summary

このチャレンジではreplay attack対策のフィルターや無効化になった暗号化されたパスワードが与えられます。
replay attack対策のフィルターはBase64文字列を比較する実装であるため、改ざんしたBase64文字列をチャレンジサーバーに与えることでフィルターをバイパスできます。また、有効なパスワードへの変更はBase64 Malleabilityを元に構成されたDecryption Oracleを使用してキーストリームを復号することで行うことができます。

### Note: Base64デコーダのMalleabilityがアプリケーションに与える影響の可能性について

Chatzigiannisらは各言語のBase64デコーダを調査し、ビットレベルで改ざんしたBase64文字列がどのようにデコードされるかを詳しく調査しました\[[CC22][1]{:target="_blank"}\]。
この論文で報告されているBase64のMalleabilityの有無はデコーダの実装に依存します。

そして、Chatzigiannisらは該当するデコーダーを使用してBase64文字列が一意である前提で実装されているアプリケーションに対して攻撃者が冪等性チェックをバイパスし、ログの不一致、DoS、データベースのエントリ重複などを引き起こす可能性があると指摘しています。
また、対策としては以下のいずれかの対策方法を挙げています ( Section 3 )。

- 開発者がバイナリ入力とそのbase64表現との間に一意の対応があると仮定しないこと
- "malleability-resistant"であるライブラリを使用すること
- 外部から入力されたBase64文字列はそのまま使用せず、デコードしたあとに再エンコードしてから使用する
- 恒久的な緩和策は、デコードにおいてパディングビットの検証を行う

## 本題: Challengeの技術的な解説

### Assumption

Playerに与えられる情報

- 無効化された認証トークン
- ソースコード
  - client.py: 認証トークンの仕様について記述
  - server.py: 認証トークンの再発行、復号処理、認証トークンの検証処理
  - challenge_server.py: TCPサーバー。server.pyへのアクセスをPlayerに提供。

当日に配布したソースコードはここにあります。  
[https://github.com/nya384/LINECTF2023-CRYPTO-Malcheeeeese](https://github.com/nya384/LINECTF2023-CRYPTO-Malcheeeeese){:target="_blank"}

### Outline

`nc`コマンドでサーバーに接続すると以下のフォーマットの認証トークン `AUTHENTICATION_TOKEN` を貰えます。 ( フォーマットはclient.py参照 )

- iv : 8 Bytes
- password : 12 Bytes
- token : 15 Bytes
- signature : 64 Bytes ( Ed25519 )
- `AUTHENTICATION_TOKEN = Base64Enc(iv)|| Base64Enc ( AES-256-CTR-Enc( password || token || signature ) )`
- AUTHENTICATION_TOKEN length : 136 Bytes

しかし、与えられる `AUTHENTICATION_TOKEN` に含まれる `iv` は `replay_attack_filter_for_iv` によって Banded Listに入っています。また、同様に `signature` も `replay_attack_filter_for_sig` によって Banded Listに入っています。加えて、`server.py` を読むとフラグを獲得するためのパスワードが変更されており、`AUTHENTICATION_TOKEN`の前半に埋め込まれた暗号化された未知のパスワードを`cheeeeese`へ改ざんする必要があります。

まとめるとFLAGを得るには以下の3つの障壁をうまく回避する必要があります。

1. `iv`の再利用の検知をバイパスする
2. `signature`の再利用の検知をバイパスする
3. passwordのパートをFLAGを獲得可能なpasswordへ改ざんする

このような問題の設定を踏まえたうえでこの Challenge を解くには2つの方法があります。

- 方法A. Base64 Malleability\[[CC22][1]{:target="_blank"}\] によって`iv`, `signature`のフィルターを回避する。passwordは復号成功時にLengthが与えられるのでそれを利用してPadding Oracle Attackに似た攻撃を実施してKeyStreamを復元する
- 方法B. 登録された `iv` 以外のIVを使用する。各Byteごとに十分な数の暗号文を集め、KeyStreamを1バイトずつ総当りする。KeyStreamがただしいかどうかは復号した平文が全てBase64のコードに当てはまっているか、もしくは当てはまっていないかで判定ができる。

私の想定解法は`方法A`です。提出いただいたwriteupは楽しく読ませていただきました。中には方法B ( これもいくつか亜種があります ) で解いたかたもいらっしゃいました。
`方法B`に関しては作問ミスによる非想定解です。署名の検証パートでbase64のデコード失敗のエラーを署名の検証失敗のエラーと区別すべきではありませんでした。

今回は`方法A`での解法を解説したいと思います。
このChallengeは`方法A`では Step-by-Stepで解けるように設計しました。
Base64 Malleabilityがこのチャレンジの根底にあるアイデアです。
Base64 Malleabilityで`iv`のフィルターを回避できることに気づけば残りのステップに進むのは難しくないと考えました。

1. `iv`の再利用の検知をバイパスする : 平文に対するBase64 Malleability
2. `signature`の再利用の検知をバイパスする : Base64 Malleability + CTR Bitflip
3. `encrypted password`の書き換え : Base64 Oracle Attack with Base64 Malleability in Python3


### 1. IVの再利用の検知バイパス

このチャレンジにおける`iv`はAES-CTRモードへの入力です。
`iv`はサーバー接続時に与えられる認証トークンに含まれており、それは平文として与えられます。
`clinet.py` から、`iv`のサイズは 8 Bytes です。
また、`Base64Enc( iv )`の長さは 12 Bytes です。


このように `server.py` で認証トークンに含まれるIVが `replay_attack_filter_for_iv` リストに登録されます。
また `iv` と `aes_key` は固定です。

```python
# server.py

# for authentication
previous_iv_b64 = base64.b64encode(previous_aes_iv)

replay_attack_filter_for_iv = [previous_iv_b64]
```

```python
# server.py

    # iv reuse detection
    if iv_b64 in replay_attack_filter_for_iv:
        ret = {
            "is_iv_verified" : False,
            "is_pwd_verified" : False,
            "pwd_len" : -1,
            "pwd_error_number" : -1,
            "pwd_error_reason": "",
            "is_sig_verified" : False,
            "sig_error_number" : -1,
            "sig_verification_reason": "iv reuse detected",
            "flag" : flag
        }
        return ret
```

そのため、`replay_attack_filter_for_iv` フィルターによって、
サーバーから与えられた認証トークンをそのままサーバーに与えると `"iv reuse detected"` エラーによって、
先へ進むことができません。

ここで`replay_attack_filter_for_iv`に登録される文字列のフォーマットに着目します。
サーバーは **Base64フォーマット** のIVをフィルターに登録しており、フィルタリングもBase64文字列に対して行います。
つまり、もし正規の`Base64Enc( iv )`とは異なるBase64文字列で元の`iv`を表現できればフィルターを回避しつつ、与えられた`iv`を使用できます。

#### Base64のパディング

Base64のMalleabilityについて説明するためにまずは Base64のパディングについて説明します。
Base64はencode時に入力されたビット列を6bitごとに分割し、
24bitずつBase64の変換表に基づいてBase64文字列を生成します。
そして、ビット列が24の倍数ではなかった時に`0`(ビットパディング)と`=`(Base64文字列のパディング)でパディングが行われます。

```python
# from server.py
AES_IV_HEX = "04ab09f1b64fbf70"
aes_iv = bytes.fromhex(AES_IV_HEX) # 8 Bytes
base64.b64encode(aes_iv) # 12 Bytes
# => b'BKsJ8bZPv3A='
```

今回のIVは `server.py` より、IVが8 Bytesであるので、
`0`でパディングされるビット数は `6-((8*8) mod 6) = 2` bits です。

よってパディングしたOriginal dataとBase64文字列の末尾4Bytesの対応表はこのようになります。


|Original data ( bit )  | 1 0 1 1 1 1 | 1 1 0 1 1 1 | 0 0 0 0 0 0 | N/A |
|Base64                  |        v     |       3       |       A      | = |


上記の表にわかりやすく印をつけたものが下の表です。このケースでは`{0 0}` が`0`パディングです。

|Original data ( bit )  | 1 0 1 1 1 1 | 1 1 0 1 1 1 | 0 0 0 0 {0 0} | N/A |
|Base64                 |       v      |      3       |       A        |   =  |

#### Base64 Malleability implementation in Python

ここで、元論文\[[CC22][1]{:target="_blank"}\]より、
Pythonの標準base64ライブラリはDecode時に`0`パディングビットを無視して暗黙的なunpaddingをします。

例えば `v3B=` は末尾の`{0 1}`が無視されるので `v3A=` と同じ文字列へデコードされます。

|Original data ( bit )  | 1 0 1 1 1 1 | 1 1 0 1 1 1 | 0 0 0 0 {0 1} | N/A |
|Base64                 |      v      |      3      |        B      |  =  |

```
-> Implicit unpadding
| 1 0 1 1 1 1 | 1 1 0 1 1 1 | 0 0 0 0 

-> Slice per 8-bits
| 1 0 1 1 1 1 1 1 | 0 1 1 1 0 0 0 0 |

-> Decode to original data
0xbf70
```

実際に Python3で `v3A=` (正規のBase64文字列) と`v3B=` (改ざんしたBase64文字列) をデコードすると同じデータ`bf70`へ復元されます。

```
> python3
>>> import base64
>>> base64.b64decode(b'v3A=').hex()
'bf70'
>>> base64.b64decode(b'v3B=').hex()
'bf70'
```

したがって、IVの末尾を `v3A=` から `v3B=` に置き換えることで
`replay_attack_filter_for_iv` フィルターをバイパスできます。
フィルターに登録されているオリジナルのivが`BKsJ8bZPv3A=`なので、上記の例と同様に末尾を`A=`から`B=`に変更します。

`exploit_iv=b'BKsJ8bZPv3B='.hex()`

### 2. signatureの検証バイパス

`server.py` では認証トークンに含まれる `token` が `acceptable_token` リストに登録されています。
また、 `signature` が `replay_attack_filter_for_sig` リストに登録されています。


```python
# server.py
# Input : b64token_signature : base64 encoded token+signature, verifier, verify_counter
# Output:
# - Is signature verification successful? ( True / False )
# - Error Code ( 0, 1, 2, 3, 4 )
# - Error Message
def verify_signature(b64token_signature, verifier, verify_counter):
    b64token = b64token_signature[:20]
    b64signature = b64token_signature[20:]

    if verify_counter > 1:
        return False, 1, "Err1-Verification limit Error"

    if b64signature in replay_attack_filter_for_sig:
        return False, 2, "Err2-Deactived Token"
    
    try:
        token = base64.b64decode(b64token)
        signature = base64.b64decode(b64signature)
    except:
        return False, 3, "Err3-Base64 decoding error"
    
    try:
        verifier.verify(token, signature)
        if token in acceptable_token:
            return True, 0, "verification is successful"
    except ValueError:
        pass

    return False, 4, "Err4-verification is failed"

```

`signature` は IV filter bypassと同じようにBase64 Malleabilityでフィルターをバイパスすればよさそうです。
つまり、`iv`の時のように `signature` の改竄すべき位置を特定し、その1 Byteのみを改竄すれば良いと予想できます。

しかし、 `signature` は CTRモードで暗号化されているので以下の2つの問題をクリアする必要があります。

1. 平文がわからない暗号文をどのように改ざんするか
2. 署名の改竄すべき位置の特定
3. どのような変更を加えるべきを探索

ここで、`1`については`token`と`signature`がCTRモードで暗号化されていることから、Bitflipによって暗号文を改竄することができることがわかります。
しかし`2`と`3`については工夫が必要です。特に `verify_counter` によって認証リクエストは1回のセッションで 2度までしか行うことができず、セッションごとに `token` と `signature` はランダムに生成されるため同一のセッション<sup>*1</sup>では `brute force attack` はできなさそうです。

- (*1) : `3`については複数セッションをまたいでランダムに改ざんすればいつか正解に当たります。

#### Finding modification targets

ここでもう一度`AUTHENTICATION_TOKEN`のフォーマットを見直します (client.pyより) 。

- iv : 8 Bytes
- password : 12 Bytes
- token : 15 Bytes
- signature : 64 Bytes ( Ed25519 )
- `AUTHENTICATION_TOKEN = Base64Enc(iv)|| Base64Enc ( AES-256-CTR-Enc( password || token || signature ) )`
- AUTHENTICATION_TOKEN length : 136 Bytes

`token` と `token` を署名した `signature` はサーバー接続時に与えられる認証トークンに含まれており、
`AES-256-CTR` で暗号化されています。
そして、`iv`, `aes_key` は固定されています。Playerは`aes_key` を知ることができません。

`token` のサイズは 15 Bytes、 `signature` のサイズは 64 Bytesであることがわかります。
Base64でエンコードした場合はもとの長さはは4/3倍になるので、パディングを含めるとBase64Enc( `token || signature` ) のサイズは 108 Bytes です。

では、`2. 署名の改竄すべき位置の特定`について考えます。
改ざんすべき位置は改ざん対象のペイロードの長さからBase64のパディングビット数を計算することで特定できます。

まず、つまり改ざんすべき対象を整理します。
対象は`payload = base64(password||token||signature)`です。
そして、`password||token||signature` の長さは
`12+15+64=91` Bytesです。
そして、 `91*8=728` bit は 24 の倍数ではないです。
よって、`0`パディングされるビット数は`6 - ( 91*8 mod 6 ) = 4` bits であることがわかります。

そして、Base64文字列の末尾3バイトに着目すると、平文の`base64(password||token||signature)`の末尾3Byteは以下のようになることがわかります。  
( 未知のBase64文字は `Unknown` 、Original dataの未知bitは`x`, `y` と表記しています。
また、`0`パディングビットを `{0 0 0 0}`でハイライトしています。)

|Original data ( bit ) | x y {0 0 0 0} | N/A  | N/A |
|Base64                |    Unknown    |  =   |  =  |

つまり、ここのBase64文字の`Unknown`は `x, y` で決定されます。
これで、`Unknown`の候補を64通りから `2^2=4` 通りに削減できました。  
このときの具体的な`x`と`y`の候補はこの4つに絞られます。   
cf. See Base64 Table [https://en.wikipedia.org/wiki/Base64](https://en.wikipedia.org/wiki/Base64)

```
A ( 000000 ): x=0, y=0
Q ( 010000 ): x=0, y=1
g ( 100000 ): x=1, y=0
w ( 110000 ): x=1, y=1
```


#### Bitflip on CTR mode

ここで、Bitflipを説明します。
CTRモードはストリーム暗号のように振る舞うモードであるため、
実際の暗号化は

```
keysteam = AES-256 (iv || counter , key)
C = P xor keysteam
```

このように排他的論理和によって暗号化されます。
つまり、暗号文の任意のビットを反転すると、復号時の平文も反転されます。

#### Modify encrypted signature

ここまでわかったことを組み合わせてCTRに対するBitflipとBase64 Malleabilityを使ったフィルターバイパスを行います。

`Unknown`の候補である `A`, `Q`, `g`, `w` のASCII文字コードは
```
A 01000001
Q 01010001
g 01100111
w 01110111
```
です。
このようにどの位置のビットを操作するかはASCIIコード表とBase64の変換表の両方から考える必要があります。
改ざん用のbit列`input`が満たすべき条件は以下の3つです。

- `Unknown xor input` がASCII文字であること
- さらに`Unknown xor input`ASCII文字がBase64変換表に存在する文字であること
- オリジナルの文字 ( `A`, `Q`, `g`, `w` ) と変更後の文字のBase64の変換コードの上位2ビットが一致していること

そして、条件を満たすビット列の例はこちらです。

- For `A`, `Q`, `g` : `00001000`
- For `w` : `00001111`

`A, Q, g`は `00001000` とxorを取った場合にBase64の変換表に存在する文字列になり、元の文字とのBase64変換コードと上位2ビットが一致します。
しかし、`w`については`w xor 00001000` をするとASCIIコード表では`0x7F ( DEL )`となり、Base64の変換表に存在しないです。

なので、まずは`A, Q, g` 用の exploitとして、`AES-CTR-Enc(Unknown) xor 00001000`をサーバーに与えて、サーバーに`Unknown xor 00001000`でバイパスが成功するか確かめます。
もし、 `Unknown` が `A`, `Q`, `g` のいずれかであったときはフィルターのバイパスに成功します。
もし、その時にBase64 Decoding errorが出た場合は、`w`用のexploitとして`AES-CTR-Enc(Unknown) xor 00001111`をサーバーに与えて、サーバーに`Unknown xor 00001111`の計算を行わせることでフィルターをバイパスできます。
その場合は`w xor 00001111 = 0x78 ( x )` となるのでBase64の変換表かつ、上位2ビットを変更しない条件を満たせます。

ここまでの説明のとおりに実装したsolverはこちらです。

```python
# solver.py
def gen_exploit_to_bypass_replay_attack_filter_for_sig(iv_hex, modified_encrypted_password, nc):
    modified_signature = b""
    for i in [0b1000, 0b1111]:
        modified_signature = encrypted_signature
        modified_signature = encrypted_signature[:-3] + strxor(bytes([modified_signature[-3]]), bytes([i])) + encrypted_signature[-2:]
        ret = call_decrypt(iv_hex+(modified_encrypted_password+encrypted_token+modified_signature).hex(), nc)
        if True==ret['is_sig_verified']:
            return True, modified_signature, ret['flag']
    return False, None
```

### 3. passwordの検証のバイパス

`server.py` では認証可能なパスワード`cheeeeese`が `acceptable_password` リストに登録されています。
しかし、 認証トークンに含まれる `password` は`AES-256-CTR` 暗号化されており、 `acceptable_password` リストに登録されていないです。

ここで`password`の仕様を確認します。
`clinet.py` から、`password` のサイズは 12 Bytesであることがわかります。
そのことから、Base64Enc( `password` ) のサイズは 16 Bytes であることがわかります。
これはAESのブロックサイズ ( 16 Bytes = 128 bits ) と同じです。



```python
# server.py
acceptable_password = [b"cheeeeese"] # cf. previous password ( PASSWORD_HEX ) was removed
```
つまり、認証トークンを改竄して、暗号化されたパスワードを `cheeeeese` に変更することでpasswordの検証をバイパスできる。

ここで、Base64のDecoding処理に着目してみる。

```python
# server.py
# Input : b64password : base64 encoded password
# Output:
# - Is password verification successful? ( True / False )
# - raw passowrd length
# - Error Code ( 0, 1, 2 )
# - Error Message
def verify_password(b64password):
    try:
        password = base64.b64decode(b64password)
    except:
        return False, -1, 1, "Base64 decoding error"

    if password in acceptable_password:
        return True, len(password), 0, "Your password is correct!"
    return False, len(password), 2, "Your password is incorrect."
```

\[[CC22][1]{:target="_blank"}\]を踏まえた上で、`verify_password`に着目すると

- 1. Python3の標準base64 decoderは他の言語にないBase64 Malleabilityを持っている\[[CC22][1]{:target="_blank"}\]。
- 2. オラクルはBase64デコードの成功/失敗とDecodeした後のパスワードの長さを知らせてくれる。

このパスワード検証に対して、Oracle Attackを実行して、パスワードパートのキーストリームを復元できそうです。
もし、キーストリームを復元できれば暗号化されたパスワードを `cheeeeese` に変更することができます。  

#### Extra Base64 Malleability in Python3 Base64 Decoder

元論文\[[CC22][1]{:target="_blank"}\]でPython Base64 Decoderの特徴的なMalleabilityが報告されています。
まず、次のBase64文字列をDecodeした結果を見てみましょう。

```bash
> python3
>>> import base64

# 0.Encode/Decode original text
>>> base64.b64encode(b"0123456789ab")
b'MDEyMzQ1Njc4OWFi'
>>> base64.b64decode(b'MDEyMzQ1Njc4OWFi')
b'0123456789ab'

# 1.Non-Base64 characters are ignored.
>>> base64.b64decode(b'MDEyMz<<<Q1Njc4OWFi')
b'0123456789ab'

# 2.If there is a terminating Base64 character ('=') in the middle, anything after it is ignored.
>>> base64.b64decode(b'MDE=yMzQ1Njc4OWFi') # same as base64.b64decode(b'MDE=')
b'01'
>>> base64.b64decode(b'MD==EyMzQ1Njc4OWFi') # same as base64.b64decode(b'MD==')
b'0'

# 3.If there is no '=' at the 4N th character, it is ignored.
>>> base64.b64decode(b'MDEy=MzQ1Njc4OWFi')
b'0123456789ab'

# 4. When `=` is followed by three or more in a row, it may be ignored even if there is '=' in the 4N th character.
>>> base64.b64decode(b'M===DEyMzQ1Njc4OWFi')
b'0123456789ab'
```

これらのケースのうち、Malleability`1`はPythonのBase64デコーダーがBase64文字列以外を無視することを示しています。
Malleability`2`は`=`より後ろのBase64文字列が無視されることを示しています (`3`, `4`のケースを除く)。
この`1`と`2`を組み合わせるとサーバーから与えられるDecode後のパスワードの長さを用いることで任意バイト目が'='となるときとそうでない時を識別でき、Oracle Attackを実施できます。

 
#### Base64 Decoding Oracle Attack on CTR mode

まずは、Malleability`2`を使用します。
```python
# 1.Non-Base64 characters are ignored.
>>> base64.b64decode(b'MDEyMz<<<Q1Njc4OWFi')
b'0123456789ab'

# 2.If there is a terminating Base64 character ('=') in the middle, anything after it is ignored.
>>> base64.b64decode(b'MDE=yMzQ1Njc4OWFi') # same as base64.b64decode(b'MDE=')
b'01'
>>> base64.b64decode(b'MD==EyMzQ1Njc4OWFi') # same as base64.b64decode(b'MD==')
b'0'
```

Extra Malleability`2`の注意すべきポイントとして、Malleability`4` により、`=` を3つ以上連続で続けると、Decoderによって`=`は無視されてしまいます。
```python
# 4. When `=` is followed by three or more in a row, it may be ignored if there is '=' in the 4N th character.
>>> base64.b64decode(b'M===DEyMzQ1Njc4OWFi')
b'0123456789ab'
```

以上のMalleabilityから次の方針でOracle Attackを実行するとキーストリームを復元できます。

1. まずはMalleability`2` を使用して、`4N` バイト目と`4N-1` バイト目が `=` となる暗号文を探索する。`=` はパディングであるため、パスワードの文字数が減った時に `=` であるとわかる。
2. Malleability`1` のDecoderに無視される文字 ( e.g., `<` ) を2文字使用して残りのBase64文字を `4N` バイト目と`4N-1` バイト目相当の位置にシフトする。
3. シフトしたBase64文字列に対してMalleability`2`を使用する。`4N` バイト目と`4N-1` バイト目が `=` となる暗号文を探索する。
4. 残った先頭の1, 2バイト目が「Decoderに無視される文字」となる場合を探索する。
5. Decode時に `b'cheeeeese'` となる暗号文を生成する。
  - 5-1. 1, 2バイト目は「Decoderに無視される文字」となる暗号文を置く。
  - 5-2. 3バイト目以降に `b'Y2hlZWVlZXNl' = base64.b64encode(b'cheeeeese')` を置く。
  - 5-3. 合計が16 Bytesとなるように末尾の2バイトに「Decoderに無視される文字」となる暗号文を置く。

この方針で実装したSolverは以下のとおりです。

```python
# solver.py
import base64, json
from Crypto.Util.strxor import strxor
from pwn import remote

SERVER_ADDRESS = '34.85.9.81'
PORT = 13000


AES_IV_HEX = "04ab09f1b64fbf70"
aes_iv = bytes.fromhex(AES_IV_HEX) # b64encode(aes_iv)==b'BKsJ8bZPv3A='


# params length ( bytes ) from client.py
IV_LEN = 8
PASSWORD_LEN = 12
TOKEN_LEN = 15
SIGNATURE_LEN = 64

B64_IV_LEN = len(base64.b64encode(b"a"*IV_LEN))
B64_PASSWORD_LEN = len(base64.b64encode(b"a"*PASSWORD_LEN))
B64_TOKEN_LEN = len(base64.b64encode(b"a"*TOKEN_LEN))
B64_SIGNATURE_LEN = len(base64.b64encode(b"a"*SIGNATURE_LEN))

def call_decrypt(data, nc):
    nc.send(data)
    ret = ""
    while True:
        ret = nc.recvline().decode('utf-8')
        if len(ret)==0 or not "Input" in ret:
            if "Bye" in ret:
                print(ret)
            break
    return json.loads(ret)


def gen_exploit_to_bypass_replay_attack_filter_for_sig(iv_hex, modified_encrypted_password, nc):
    modified_signature = b""
    for i in [0b1000, 0b1111]:
        modified_signature = encrypted_signature
        modified_signature = encrypted_signature[:-3] + strxor(bytes([modified_signature[-3]]), bytes([i])) + encrypted_signature[-2:]
        ret = call_decrypt(iv_hex+(modified_encrypted_password+encrypted_token+modified_signature).hex(), nc)
        if True==ret['is_sig_verified']:
            return True, modified_signature, ret['flag']
    return False, None

def get_exploit_to_bypass_replay_attack_filter_for_iv():
    exploit_iv = b'BKsJ8bZPv3B='
    #aes_iv_b64 = base64.b64encode(aes_iv) # b'BKsJ8bZPv3A='
    #print("b64decode(b'BKsJ8bZPv3A=')==b64decode(b'BKsJ8bZPv3B=')")
    #print(base64.b64decode(aes_iv_b64)==base64.b64decode(exploit_iv))
    return exploit_iv
    

def base64_oracle(iv_hex, nc):
    max_len = PASSWORD_LEN
    modified_encrypted_password = encrypted_password

    # Oracle Attack based on length
    # calc 3nd-4rd, 7-8th, 11-12th, 15-16th bytes for Base64ed passowrd
    for i in [15, 11, 7, 3]:
        c = encrypted_password
        for j in reversed(range(i-1, i+1)):
            for k in range(1, 256):
                c = c[:j] + strxor(encrypted_password[j:j+1], bytes([k])) + c[j+1:]
                ret = call_decrypt(iv_hex+(c+encrypted_token+encrypted_signature).hex(), nc)
                if -1 != ret['pwd_len'] and ret['pwd_len'] < max_len:
                    max_len = ret['pwd_len']
                    modified_encrypted_password = modified_encrypted_password[:j] + bytes([c[j]]) + modified_encrypted_password[j+1:]
                    break

    # Oracle Attack with padded encrypted password
    # calc 5-6th, 9-10th, 13-14th bytes for Base64ed passowrd
    padded_encrypted_password = encrypted_password[:2] + strxor(b"<<" ,strxor(modified_encrypted_password[2:4], b"==")) + encrypted_password[4:]
    max_len = 12
    for i in [13, 9, 5]:
        #padding = (i+1) % 4 # always 2
        c = padded_encrypted_password
        for j in reversed(range(i-1, i+1)):
            for k in range(1, 256):
                c = c[:j] + strxor(encrypted_password[j:j+1], bytes([k])) + c[j+1:]
                ret = call_decrypt(iv_hex+(c+encrypted_token+encrypted_signature).hex(), nc)
                if -1 != ret['pwd_len'] and ret['pwd_len'] < max_len:
                    max_len = ret['pwd_len']
                    modified_encrypted_password = modified_encrypted_password[:j] + bytes([c[j]]) + modified_encrypted_password[j+1:]
                    break

    # Finds chars in 1st-2nd bytes for Base64ed passowrd, which ignored by Python base64.b64decode()
    padded_encrypted_password = encrypted_password[:13] + strxor(b"<<<" ,strxor(modified_encrypted_password[13:], b"==="))
    for i in [1, 0]:
        c = padded_encrypted_password
        for j in range(1, 256):
            c = c[:i] + strxor(encrypted_password[i:i+1], bytes([k])) + c[i+1:]
            ret = call_decrypt(iv_hex+(c+encrypted_token+encrypted_signature).hex(), nc)
            if -1 != ret['pwd_len']:
                modified_encrypted_password = modified_encrypted_password[:i] + bytes([c[i]]) + modified_encrypted_password[i+1:]
                break

    return modified_encrypted_password

if __name__=="__main__":
    nc = remote(SERVER_ADDRESS,PORT)
    ret = nc.read().decode('utf-8')
    previous_auth_token = bytes.fromhex(ret.strip().split(":")[1])
    # cf.
    # base64.b64encode(aes_iv) == previous_auth_token[:B64_IV_LEN]
    # => True
    encrypted_password = previous_auth_token[B64_IV_LEN:B64_IV_LEN+B64_PASSWORD_LEN]
    encrypted_token = previous_auth_token[B64_IV_LEN+B64_PASSWORD_LEN:B64_IV_LEN+B64_PASSWORD_LEN+B64_TOKEN_LEN]
    encrypted_signature = previous_auth_token[B64_IV_LEN+B64_PASSWORD_LEN+B64_TOKEN_LEN:B64_IV_LEN+B64_PASSWORD_LEN+B64_TOKEN_LEN+B64_SIGNATURE_LEN]

    exploit_iv = get_exploit_to_bypass_replay_attack_filter_for_iv()

    modified_encrypted_password = base64_oracle(exploit_iv.hex(), nc)

    # change modified_encrypted_password[2:] to \x00*14
    modified_encrypted_password = modified_encrypted_password[:2] + strxor(b"="*(len(modified_encrypted_password)-2), modified_encrypted_password[2:])

    # change modified_encrypted_password[2:] to b'Y2hlZWVlZXNl<<' ( b'cheeeeese' with maleabilty padding)
    modified_encrypted_password = modified_encrypted_password[:2] + strxor(b'Y2hlZWVlZXNl<<', modified_encrypted_password[2:])
    nc.close() # reset server verification count

    nc = remote(SERVER_ADDRESS,PORT)
    ret = nc.read().decode('utf-8')
    previous_auth_token = bytes.fromhex(ret.strip().split(":")[1])
    encrypted_token = previous_auth_token[B64_IV_LEN+B64_PASSWORD_LEN:B64_IV_LEN+B64_PASSWORD_LEN+B64_TOKEN_LEN]
    encrypted_signature = previous_auth_token[B64_IV_LEN+B64_PASSWORD_LEN+B64_TOKEN_LEN:B64_IV_LEN+B64_PASSWORD_LEN+B64_TOKEN_LEN+B64_SIGNATURE_LEN]

    _, modified_signature, flag = gen_exploit_to_bypass_replay_attack_filter_for_sig(exploit_iv.hex(), modified_encrypted_password, nc)
    
    print('flag_is:')
    print(flag)
    nc.close()

```

FLAG;  
`LINECTF{c576ff588b07a5770a5f7fab5a92a0c2}`

## How to developed this challenge

私がどのように作問したかについて Discordで質問を受けましたのでここに書きます。

2022年の3月末頃に[Papers update in last 7 days - IACR Cryptology ePrint Archive](https://eprint.iacr.org/days/7){:target="_blank"}からこの\[[CC22][1]{:target="_blank"}\]を読みました。

この論文を初めて読んだときに、Encode-then-EncryptとDecryption Oracleの仮定の下でチャレンジを構成できそうだと直感的に感じました。
その後調査を開始し、一部のMalleability issueは過去に知られていることがわかりました \[[Valsorda19][2]{:target="_blank"}\]。
ただし、私が調べた限りではそれを題材にしたCTFのチャレンジはありませんでした ( もし、どなたかご存知でしたら教えて下さい )。
その後、作問に取り掛かり、他のCTFで同じようなチャレンジが出題されないことを祈りながらLINE CTF2023の開催を待ちました。本当にただそれだけです。

```
For English speaker;

Some players asked me on Discord about how I developed this challenge, so here it is.

I found [CC22] (https://eprint.iacr.org/2022/361) paper in https://eprint.iacr.org/days/7 in the end of March 2022.

When I first read this paper, I felt that I could construct a challenge under the assumption of Encode-then-Encrypt and Decryption Oracle.
I then started a survey and found that some malleability issues have been known in the past [Valsorda19] (https://twitter.com/filosottile/status/1157776085955878913).
However, as far as I could find, there was no CTF challenge on that issue (if anyone knows of past challenge, please let me know ).
So I developed this challenge and waited for the LINE CTF2023, hoping that a similar challenge would not be published in other CTFs. That's really all.
```
