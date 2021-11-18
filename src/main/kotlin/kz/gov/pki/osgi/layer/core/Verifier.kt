package kz.gov.pki.osgi.layer.core

import com.beust.klaxon.JsonReader
import com.beust.klaxon.Klaxon
import java.security.cert.X509Certificate
import java.security.KeyStore
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation
import kz.gov.pki.osgi.layer.api.NCALayerJSON
import kz.gov.pki.kalkan.x509.X509CertStoreSelector
import kz.gov.pki.kalkan.util.CollectionStore
import kz.gov.pki.kalkan.util.Store
import org.json.JSONObject
import java.io.StringReader

fun verifyCMS(data: ByteArray, xstore: Store): String {
	val cms = CMSSignedData(data)
	val signers = cms.signerInfos
	val isVerified = signers?.signers?.firstOrNull()?.let { signer ->
		signer as SignerInformation
		val cert = xstore.getMatches(X509CertStoreSelector.getInstance(signer.sid)).first() as X509Certificate
		with(cert) {
			println("Certificate: [$serialNumber] [$subjectX500Principal] [$notAfter]")
		} 
		signer.verify(cert, "KALKAN")
	} ?: false
	return if (isVerified) {
		String(cms.signedContent.content as ByteArray)
	} else "{}"
}

fun initCertStore(): Store {
	val inStream = NCALayer::class.java.getResourceAsStream("/trusted.jks")
	val certList = mutableListOf<X509Certificate>()
	inStream.use {
		val ks = KeyStore.getInstance("JKS", "KALKAN")
		ks.load(inStream, "knca".toCharArray())
		val aliases = ks.aliases()
		while (aliases.hasMoreElements()) {
			certList.add(ks.getCertificate(aliases.nextElement()) as X509Certificate)
		}
	}
	return CollectionStore(certList)
}

fun retrieveJSON(data: ByteArray): NCALayerJSON {
	val xstore = initCertStore()
	val verifiedJSON = verifyCMS(data, xstore)
	return NCALayerJSON.parseJSON(verifiedJSON)
}

fun verifyFromJson(data: ByteArray): String {

	val jsonFile = NCALayer::class.java.getResourceAsStream("/ncalayer.json")
	val file = String(jsonFile.readBytes())


	val jsonBundles = mutableListOf<String>()

	val jsonObject = JSONObject(file)
	val bundlesNcaLayer = jsonObject.getJSONArray("bundles")
	for (bund in bundlesNcaLayer) {
		val bundle = String()
		jsonBundles.add(bund.toString())
		println(bund.toString())
	}

//	val result = ""
//	val klaxon = Klaxon()
//	val jsonBundles = mutableListOf<NCALayerBundleJsonParsingElement>()
//	JsonReader(StringReader(data)).use { reader ->
//		reader.beginArray {
//			while (reader.hasNext()) {
//				val jsonBundleElement = klaxon.parse<NCALayerBundleJsonParsingElement>(reader)
//				jsonBundles.add(jsonBundleElement!!)
//			}
//		}
//	}

	return ""
}

class NCALayerBundleJsonParsingElement(val name: String)