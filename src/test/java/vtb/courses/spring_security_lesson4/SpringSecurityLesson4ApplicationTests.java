package vtb.courses.spring_security_lesson4;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.shaded.gson.Strictness;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;
import org.springframework.context.annotation.Bean;
import vtb.courses.spring_security_lesson4.security.RsaKeyManager;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.text.ParseException;
import java.util.*;

@SpringBootTest
class SpringSecurityLesson4ApplicationTests {

	@Test
	void contextLoads() {
	}

	@Test
	void generateRSA() throws JOSEException, IOException {

		// Мапа из которой сформируем потом json
		Map<String, Object> keysForJson = new HashMap<>();
		// Массив сгенерённых объектов RSAKey
		RSAKey rsaJWK[] = new RSAKey[2];
		// Список представлении RSAKey в виде мапы ключ-значение, для дальнейшего формирования JSON
		List<Map<String, Object>> keyList = new ArrayList<>();
		keysForJson.put("keys", keyList);

		// Генерируем RSA ключи
		for (int i = 0; i < rsaJWK.length; i++) {
			rsaJWK[i] =	new RSAKeyGenerator(2048)
							.keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
							.keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
							.issueTime(new Date()) // issued-at timestamp (optional)
							.generate();
			keyList.add(rsaJWK[i].toPublicJWK().toJSONObject());
		}
		String jsonStr = JSONObjectUtils.toJSONString(keysForJson);
		System.out.println(jsonStr);

		FileWriter jsonWriter = new FileWriter("./src/main/resources/keyset.json", false);
		jsonWriter.write(jsonStr);
		jsonWriter.close();

		// Формируем токен и подписываем его первым ключом

		// Формируем заголовок
		JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
				.keyID(rsaJWK[0].getKeyID())
				.build();
		// Подготавливаем секцию с полезными данными
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.subject("alice")
				.jwtID(UUID.randomUUID().toString())
				.claim("scp", "ROLE_USER, ROLE_ADMIN")
				.expirationTime(new Date(new Date().getTime() + 86400 * 1000))//один день
				.build();

		// На базе RSA ключа готовим подпись
		JWSSigner signer = new RSASSASigner(rsaJWK[0]);
		// Формируем и подписываем токен
		SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
		signedJWT.sign(signer);

		// Выгружаем токен в файл
		FileWriter tokenWriter = new FileWriter("./src/main/resources/alice.token", false);
		tokenWriter.write(signedJWT.serialize());
		tokenWriter.close();


		// Output the private and public RSA JWK parameters
//		System.out.println(jwk);

		// Output the public RSA JWK parameters only
//		System.out.println(jwk.toPublicJWK());
	}

	@Test
	public void RsaKeyManager() {
		char[] buff = new char[20000];
		try {
			FileReader jsonReader = new FileReader("./src/main/resources/keyset.json");
			int jsonLen = jsonReader.read(buff, 0, 20000);
			String jsonString = String.valueOf(buff, 0, jsonLen);
			Map<String, Object> keys = JSONObjectUtils.parse(jsonString);
			System.out.println("class = " + keys.get("keys").getClass().getName());
		} catch (FileNotFoundException e) {
			System.out.println(e.getMessage());
		} catch (IOException e) {
			System.out.println(e.getMessage());
		} catch (ParseException e) {
			System.out.println(e.getMessage());
		}

	}
}
