# كاشف (Kashef) | درع الحماية من الاحتيال والنصب الإلكتروني

[![Android CI](https://github.com/seotarek/kashef-scam-shield/actions/workflows/android.yml/badge.svg)](https://github.com/seotarek/kashef-scam-shield/actions/workflows/android.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Kotlin](https://img.shields.io/badge/Kotlin-1.9.24-purple.svg)](https://kotlinlang.org)
[![Android](https://img.shields.io/badge/Android-SDK%2024%2B-green.svg)](https://developer.android.com)

تطبيق أندرويد مفتوح وسريع مبني بأحدث معايير **Jetpack Compose** و **Material 3**، مصمم خصيصاً لحماية المستخدمين في مصر والوطن العربي من محاولات النصب المتكررة (سرقة حسابات إنستاباي، اختراق المحافظ الإلكترونية، التصيد باسم البنوك، رسائل البريد المصري المزيفة، وفخاخ التوظيف الوهمي على تليجرام).

---

## 🌟 المزايا الجوهرية (Core Features)

1. **فحص محلي فوري وآمن 100% (On-Device Zero Knowledge):**
   - التطبيق يعمل بالكامل دون طلب أي صلاحيات إنترنت (`No INTERNET permission`). لا يتم إرسال أي نصوص أو روابط لخوادم خارجية، مما يضمن سرية تامة لبياناتك.
2. **محرك التطبيع اللغوي العربي الذكي (Arabic Text Normalizer):**
   - تفكيك ومقاومة حيل التحايل الإملائي (إزالة التشكيل، توحيد الألفات والياء والتاء المربوطة، وحل المسافات المفرقة بين الحروف مثل `ت م  إ ي ق ا ف`).
3. **كشف هجمات التمويه (Camouflage Detection):**
   - التحقق من سياق الرسائل التي تستخدم روابط رسمية للتمويه لطلب رموز تأكيد سرية أو سرقة أكواد الـ OTP.
4. **فحص وتجميع مخاطر الروابط المتعددة (Multi-URL Evaluation):**
   - فحص شامل لجميع الروابط الموجودة داخل الرسالة وتحديد مستوى الخطورة العام بناءً على أشد الروابط خطورة.
5. **فحص الروابط والنطاقات (Intelligent URL Heuristics):**
   - **القائمة البيضاء الرسمية (Official Whitelist):** مطابقة النطاقات الرسمية للبنوك المصرية، شبكة إنستاباي (`instapay.eg`)، فودافون كاش، أورنج، إي آند، وي، والبريد المصري.
   - **كشف انتحال الهوية (Brand Impersonation & Typosquatting):** رصد أي محاولة لاستخدام اسم مؤسسة رسمية داخل دومين مشبوه أو نطاق فرعي مضلل.
   - **رصد النطاقات الرخيصة المشبوهة (High-Risk TLDs):** فحص النطاقات سريعة الإنشاء (`.xyz`, `.top`, `.site`, `.fun`, `.club`, `.space`).
   - **كشف اختصار الروابط وعناوين IP المباشرة وإعادة التوجيه (Open Redirects).**
6. **سجل الفحوصات المحلي الآمن (Privacy-Preserving History):**
   - حفظ سجل الفحوصات محلياً عبر Room Database مع الالتزام بمبدأ تقليل البيانات (عدم حفظ النصوص الحساسة كاملة) مع إمكانية مسح السجل بضغطة زر.
7. **التكامل المباشر مع النظام (Android System Integration):**
   - يدعم **ACTION_SEND**: مشاركة أي رسالة من واتساب أو الرسائل القصيرة لتطبيق كاشف ليفحصها مباشرة، وزر "لصق وفحص".
8. **محرك التحذير (Shareable Warning Card):**
   - توليد بطاقة تحذير أمني منسقة لمشاركتها على واتساب ومنصات التواصل لتنبيه العائلة والأصدقاء.

---

## 🏗️ الهيكلية التقنية (Architecture)

* **UI Layer:** Jetpack Compose + Material 3 + Kotlin Coroutines + StateFlow.
* **Architecture:** Clean Architecture + MVVM + Separation of Concerns.
* **Data Layer:** Room Database لحفظ سجل الفحوصات محلياً مع منع النسخ السحابي غير المشفر (`allowBackup=false`).
* **Compatibility:** Android 7.0 (API 24) فما فوق، مع جاهزية كاملة لـ Android 15 (API 35).

---

## 📁 هيكل المشروع (Project Layout)

```
kashef-scam-shield/
├── app/
│   ├── src/main/
│   │   ├── AndroidManifest.xml
│   │   └── java/eg/kashef/shield/
│   │       ├── KashefApp.kt
│   │       ├── MainActivity.kt
│   │       ├── core/
│   │       │   ├── analyzer/
│   │       │   │   ├── UrlAnalyzer.kt
│   │       │   │   └── TextMessageHeuristicAnalyzer.kt
│   │       │   ├── engine/
│   │       │   │   └── ScamShieldEngine.kt
│   │       │   ├── util/
│   │       │   │   └── ArabicTextNormalizer.kt
│   │       │   └── whitelist/
│   │       │       └── EgyptianEntitiesWhitelist.kt
│   │       ├── data/local/
│   │       │   └── ScanHistoryDatabase.kt
│   │       ├── domain/model/
│   │       │   └── Models.kt
│   │       └── ui/
│   │           ├── HomeScreen.kt
│   │           └── MainViewModel.kt
│   └── build.gradle.kts
└── settings.gradle.kts
```

---

## 🚀 التشغيل والتطوير (How to Run)

1. افتح المشروع في **Android Studio** أو محرر **Antigravity**.
2. اسمح لـ Gradle بمزامنة المكتبات (Sync Project with Gradle Files).
3. شغّل التطبيق على محاكي (Emulator) أو هاتف حقيقي عبر `Run 'app'`.
4. لتشغيل الاختبارات:
   ```bash
   ./gradlew test
   ```
