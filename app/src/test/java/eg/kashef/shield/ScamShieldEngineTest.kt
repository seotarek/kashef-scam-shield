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
    }

    @Test
    fun testOfficialNbeUrlIsSafe() {
        val result = engine.scan("موقع البنك الأهلي الرسمي: https://nbe.com.eg")
        assertEquals(RiskLevel.SAFE, result.riskLevel)
        assertTrue(result.isOfficialDomain)
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
    fun testBenignNormalConversationIsSafe() {
        val normalText = "السلام عليكم يا هندسة، الاجتماع بكره الساعة 3 عصراً في المكتب إن شاء الله."
        val result = engine.scan(normalText)
        assertEquals(RiskLevel.SAFE, result.riskLevel)
        assertEquals(0, result.score)
    }
}
