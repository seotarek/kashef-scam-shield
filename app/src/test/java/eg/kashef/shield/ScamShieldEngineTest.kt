package eg.kashef.shield

import eg.kashef.shield.core.engine.ScamShieldEngine
import eg.kashef.shield.domain.model.RiskLevel
import eg.kashef.shield.domain.model.ThreatCategory
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class ScamShieldEngineTest {

    private lateinit var engine: ScamShieldEngine

    @Before
    fun setUp() {
        engine = ScamShieldEngine()
    }

    @Test
    fun testOfficialInstaPayUrlIsSafe() {
        val result = engine.scan("برجاء الدخول على الرابط الرسمي https://www.instapay.eg/help")
        assertEquals(RiskLevel.SAFE, result.riskLevel)
        assertTrue(result.isOfficialDomain)
        assertNotNull(result.officialEntityName)
        assertEquals(0, result.score)
    }

    @Test
    fun testOfficialNbeUrlIsSafe() {
        val result = engine.scan("موقع البنك الأهلي الرسمي: https://nbe.com.eg")
        assertEquals(RiskLevel.SAFE, result.riskLevel)
        assertTrue(result.isOfficialDomain)
    }

    @Test
    fun testCamouflageAttackOfficialLinkWithOtpTheftIsDangerous() {
        // Critical test for the audit finding: Official domain used to camouflage OTP theft
        val camouflageMessage = "عزيزي العميل، لتحديث بيانات الدخول عبر موقع البنك الأهلي https://nbe.com.eg يرجى إرسال كود التحقق OTP لتأكيد الهوية فوراً"
        val result = engine.scan(camouflageMessage)
        assertEquals(RiskLevel.DANGEROUS, result.riskLevel)
        assertTrue(result.signals.any { it.category == ThreatCategory.CAMOUFLAGE_PHISHING || it.category == ThreatCategory.OTP_CREDENTIAL_THEFT })
    }

    @Test
    fun testMultipleUrlsWithOnePhishingAndOneOfficialIsDangerous() {
        // Critical test for the audit finding: Message contains both an official link and a malicious link
        val message = "تابعنا على موقعنا https://nbe.com.eg أو اضغط هنا لتأكيد الجائزة: http://nbe-gift-claim.xyz"
        val result = engine.scan(message)
        assertEquals(RiskLevel.DANGEROUS, result.riskLevel)
        assertEquals(2, result.allExtractedUrls.size)
        assertTrue(result.signals.any { it.category == ThreatCategory.BRAND_IMPERSONATION || it.category == ThreatCategory.HIGH_RISK_TLD })
    }

    @Test
    fun testArabicNormalizationDeSpacingTrickIsDetected() {
        // Critical test for audit finding: Attackers spacing letters out (ت م  إ ي ق ا ف  ح س ا ب ك)
        val sneakyText = "ت م  إ ي ق ا ف  ح س ا ب ك  البنكي، اضغط لتحديث البيانات: http://kyc-update.xyz"
        val result = engine.scan(sneakyText)
        assertEquals(RiskLevel.DANGEROUS, result.riskLevel)
        assertTrue(result.signals.any { it.category == ThreatCategory.ACCOUNT_SUSPENSION_PHISHING })
    }

    @Test
    fun testArabicDiacriticsTashkeelIsHandledCleanly() {
        // Test diacritics / tashkeel normalization
        val tashkeelText = "تَمَّ إِيقَافُ حِسَابِكَ البَنْكِي لِعَدَمِ التَّحْدِيثِ http://update-portal.fun"
        val result = engine.scan(tashkeelText)
        assertEquals(RiskLevel.DANGEROUS, result.riskLevel)
        assertTrue(result.signals.any { it.category == ThreatCategory.ACCOUNT_SUSPENSION_PHISHING })
    }

    @Test
    fun testFakeInstaPayPhishingUrlIsDangerous() {
        val result = engine.scan("لتحديث محفظتك اللحظية اضغط هنا: http://instapay-portal.site/login")
        assertEquals(RiskLevel.DANGEROUS, result.riskLevel)
        assertTrue(result.signals.any { it.category == ThreatCategory.BRAND_IMPERSONATION })
        assertTrue(result.shareableWarningText.isNotBlank())
    }

    @Test
    fun testBankSuspensionSmsPhishingIsDangerous() {
        val sms = "عزيزي العميل، تم إيقاف حسابك البنكي لعدم تحديث البيانات، يرجى التحديث لتفادي غلق الحساب: http://nbe-kyc-update.xyz"
        val result = engine.scan(sms)
        assertEquals(RiskLevel.DANGEROUS, result.riskLevel)
        assertTrue(result.signals.any { it.category == ThreatCategory.ACCOUNT_SUSPENSION_PHISHING })
        assertTrue(result.signals.any { it.category == ThreatCategory.BRAND_IMPERSONATION })
    }

    @Test
    fun testFakeEgyptPostCourierScamIsDangerous() {
        val sms = "البريد المصري: تعذر تسليم طردك البريدي بسبب نقص العنوان، يرجى سداد رسوم التوصيل: http://egyptpost-delivery.fun"
        val result = engine.scan(sms)
        assertEquals(RiskLevel.DANGEROUS, result.riskLevel)
        assertTrue(result.signals.any { it.category == ThreatCategory.FAKE_POSTAL_DELIVERY })
    }

    @Test
    fun testTelegramJobScamIsDangerous() {
        val message = "مرحبا، شركة عالمية توفر وظيفة من المنزل، مهام يوتيوب سهلة وأرباح يومية 150 دولار، اضغط هنا للبدء: http://task-payout.club"
        val result = engine.scan(message)
        assertEquals(RiskLevel.DANGEROUS, result.riskLevel)
        assertTrue(result.signals.any { it.category == ThreatCategory.TELEGRAM_TASK_SCAM })
    }

    @Test
    fun testSubdomainSpoofingIsDangerous() {
        val sneakyUrl = "ادخل حسابك عبر http://nbe.com.eg.login-portal.site/auth"
        val result = engine.scan(sneakyUrl)
        assertEquals(RiskLevel.DANGEROUS, result.riskLevel)
        assertTrue(result.signals.any { it.category == ThreatCategory.TYPOSQUATTING_DOMAIN || it.category == ThreatCategory.BRAND_IMPERSONATION })
    }

    @Test
    fun testDirectIpAddressIsFlagged() {
        val ipUrl = "لتسجيل الدخول: http://192.168.1.100/login"
        val result = engine.scan(ipUrl)
        assertTrue(result.signals.any { it.category == ThreatCategory.DIRECT_IP_ADDRESS })
    }

    @Test
    fun testBenignNormalConversationIsSafe() {
        val normalText = "السلام عليكم يا هندسة، الاجتماع بكره الساعة 3 عصراً في المكتب إن شاء الله."
        val result = engine.scan(normalText)
        assertEquals(RiskLevel.SAFE, result.riskLevel)
        assertEquals(0, result.score)
    }

    @Test
    fun testBenignBankInquiryIsSafe() {
        val inquiry = "لو سمحت هو فرع البنك الأهلي المصري في التجمع فاتح لحد الساعة 5 النهاردة؟"
        val result = engine.scan(inquiry)
        assertEquals(RiskLevel.SAFE, result.riskLevel)
        assertEquals(0, result.score)
    }

    @Test
    fun testEmptyInputGivesSafeEmptyResult() {
        val result = engine.scan("   ")
        assertEquals(RiskLevel.SAFE, result.riskLevel)
        assertEquals(0, result.score)
        assertTrue(result.allExtractedUrls.isEmpty())
    }
}
