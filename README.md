# SoTI — ابزار جامع هوش تهدید و ارزیابی IOC

**SoTI (Threat Intelligence Enrichment & IOC Assessment Workbench)** یک ابزار حرفه‌ای تحلیل و غنی‌سازی شاخص‌های تهدید (**IPv4/IPv6**، **Domain**، **URL** و هش‌های **MD5 / SHA1 / SHA256**) در دو نسخهٔ **خط فرمان (Python CLI)** و **وب‌داشبورد تعاملی (SOC Web Workbench)** است.

این پروژه توسط **Mohammad Hossein Sokhanfar** طراحی و توسعه داده شده است.  
مخزن رسمی: [https://github.com/MHSokhanfar/SoTI](https://github.com/MHSokhanfar/SoTI)

---

## ۱. پیش‌نیازها (Prerequisites)

پیش از شروع نصب، از نصب بودن ابزارهای زیر روی سیستم خود اطمینان حاصل کنید:

| پیش‌نیاز | نسخه پیشنهادی | کاربرد |
| :--- | :--- | :--- |
| **Git** | `2.30+` | دریافت کدهای مخزن از GitHub |
| **Python** | `3.10` یا بالاتر + `pip` | اجرای نسخهٔ CLI (`main.py`) و تست‌های پایتون |
| **Node.js & npm** | `Node.js 18+` (ترجیحاً `20 LTS`) | اجرای وب‌داشبورد React/Vite و سرور Express (`server.ts`) |
| **کلیدهای API** | رایگان / استاندارد | اتصال به VirusTotal، AbuseIPDB و AlienVault OTX (در حالت `--demo` یا `Sample Data` اختیاری است) |

---

## ۲. مراحل نصب (Installation)

### گام ۱: دریافت مخزن (Git Clone)
ترمینال (Terminal / Command Prompt / PowerShell) را باز کرده و پروژه را کلون کنید:

```bash
git clone https://github.com/MHSokhanfar/SoTI.git
cd SoTI
```

### گام ۲: ساخت و فعال‌سازی محیط مجازی پایتون (Virtual Environment)
برای ایزوله‌سازی وابستگی‌های پایتون، یک محیط مجازی بسازید و فعال کنید:

- **لینوکس و مک (Linux / macOS):**
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

- **ویندوز — Command Prompt (CMD):**
  ```cmd
  python -m venv venv
  venv\Scripts\activate.bat
  ```

- **ویندوز — PowerShell:**
  ```powershell
  python -m venv venv
  .\venv\Scripts\Activate.ps1
  ```
  > **نکته ویندوز:** در صورت مشاهده خطای Execution Policy در PowerShell، یک بار دستور زیر را اجرا کنید و دوباره فعال‌سازی را انجام دهید:
  > `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### گام ۳: نصب پکیج‌های پایتون (`requirements.txt`)
پس از فعال‌شدن محیط مجازی `(venv)`، وابستگی‌های نسخهٔ CLI (`requests`، `python-dotenv` و `rich`) را نصب کنید:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### گام ۴: نصب وابستگی‌های وب‌داشبورد (اختیاری — برای نسخهٔ Web UI)
اگر قصد استفاده از داشبورد تحت وب را دارید، پکیج‌های Node.js را نیز نصب کنید:

```bash
npm install
```

---

## ۳. تنظیمات کلیدهای API (Configuration)

### گام ۱: ایجاد فایل `.env` از روی `.env.example`
- **لینوکس و مک:**
  ```bash
  cp .env.example .env
  ```
- **ویندوز (CMD / PowerShell):**
  ```cmd
  copy .env.example .env
  ```

### گام ۲: وارد کردن کلیدهای API
فایل `.env` را با ویرایشگر متن باز کرده و کلیدهای دریافت‌شده از ارائه‌دهندگان هوش تهدید را قرار دهید:

```env
# کلیدهای اصلی مورد استفاده در CLI و وب‌داشبورد
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
OTX_API_KEY=your_alienvault_otx_api_key

# کلیدهای ارائه‌دهندگان تکمیلی (اختیاری)
SHODAN_API_KEY=your_shodan_api_key
THREATFOX_AUTH_KEY=your_threatfox_auth_key
URLSCAN_API_KEY=your_urlscan_api_key
```

> **نکات امنیتی و سهمیه:**
> - فایل `.env` در `.gitignore` قرار دارد و هرگز نباید در مخزن Git کامیت شود.
> - در وب‌داشبورد می‌توانید وضعیت اتصال و کلیدها را از تب **CLI & APIs** نیز مدیریت کنید و از دکمهٔ **Help** برای مشاهدهٔ مستندات دریافت کلید هر سرویس کمک بگیرید.

---

## ۴. نحوه اجرا (Usage & Execution)

### الف) اجرای نسخهٔ خط فرمان (Python CLI — `main.py`)

#### ۱. حالت تعاملی (Interactive Menu)
برای ورود به منوی تعاملی ترمینال:
```bash
python main.py
```
و برای اجرای تعاملی آفلاین با داده‌های نمونه (بدون مصرف سهمیهٔ API):
```bash
python main.py --demo
```

#### ۲. حالت دستور مستقیم (Non-Interactive)
از شاخص‌های عادی یا خنثی‌سازی‌شده (**Defanged IOCs**) مانند `1[.]2[.]3[.]4` و `hxxp://evil[.]com` پشتیبانی می‌شود:

```bash
# بررسی یک یا چند شاخص هم‌زمان در تمام منابع
python main.py --source all --indicators "1[.]2[.]3[.]4, hxxp://evil[.]com, 44d88612fea8a8f36de82e1278abb02f"

# استعلام یک IP صرفاً از VirusTotal
python main.py --source vt --indicators 8.8.8.8

# خواندن فهرست شاخص‌ها از فایل متنی
python main.py --source all --file indicators.txt

# اجرای آزمایشی با خروجی ماشینی JSON
python main.py --source all --indicators "8.8.8.8, evil[.]com" --demo --json
```

#### ۳. مدیریت بررسی‌های زمان‌بندی‌شده (Scheduled Checks)
```bash
# افزودن بررسی دوره‌ای هر ۶۰ دقیقه
python main.py --add-schedule --schedule-name "Critical IOC Watch" --source all --indicators "1[.]2[.]3[.]4, evil[.]com" --interval 60

# نمایش فهرست زمان‌بندی‌ها
python main.py --list-schedules

# اجرای فوری وظایف سررسیدشده
python main.py --run-due

# حذف یک زمان‌بندی با شناسه
python main.py --remove-schedule <SCHEDULE_ID>
```

---

### ب) اجرای نسخهٔ وب‌داشبورد (Web Dashboard — `server.ts`)

وب‌داشبورد **SoTI** شامل سرور یکپارچهٔ Express (`server.ts`) و رابط کاربری React + Vite است و از نماهای **Investigate** (آپلود فایل CSV/TXT و Failover خودکار سهمیه)، **Reports** (آمار سریع، نمودارها، تنظیم تراکم جدول، خروجی PDF و CSV تجمیعی)، **Scheduled**، **Logs** و **CLI & APIs** پشتیبانی می‌کند.

#### اجرای محیط توسعه (Development)
```bash
npm run dev
```
سپس مرورگر خود را روی آدرس زیر باز کنید:  
`http://localhost:3000`

#### اجرای نسخهٔ نهایی (Production Build)
```bash
npm run build
npm start
```

---

## ۵. ساختار پوشه‌ها و فایل‌ها (Directory Structure)

```text
SoTI/
├── api/                         # ماژول‌های ارتباط با API ارائه‌دهندگان (نسخه پایتون)
│   ├── __init__.py              # نرمال‌سازی و تشخیص نوع IOC (IP / Domain / Hash)
│   ├── virustotal.py            # رابط VirusTotal API v3
│   ├── abuseipdb.py             # رابط AbuseIPDB API v2
│   └── alienvault.py            # رابط AlienVault OTX API
├── config/                      # تنظیمات مرکزی و فایل‌های وضعیت سیستم
│   ├── settings.py              # مسیر پوشه‌ها، نسخه ابزار و پیکربندی پایه
│   ├── scheduler.py             # موتور مدیریت و اجرای بررسی‌های زمان‌بندی‌شده
│   ├── api_settings.json        # وضعیت فعال‌بودن و تنظیمات ارائه‌دهندگان وب
│   ├── quota_usage.json         # دفترچه ردیابی سهمیه روزانه و Failover خودکار
│   └── schedules.json           # فهرست زمان‌بندی‌های ذخیره‌شده
├── logs/                        # پوشه ثبت وقایع و ممیزی سیستم (Audit Logs)
│   └── soti.log                 # فایل گزارش رخدادهای اجرایی و خطاهای CLI/Backend
├── reports/                     # پوشه ذخیره خودکار گزارش‌های خروجی
│   └── soti_YYYYMMDD_HHMMSS.csv # فایل‌های گزارش CSV با رمزگذاری UTF-8-SIG (سازگار با Excel)
├── src/                         # کد منبع رابط کاربری وب (React + TypeScript + Tailwind CSS)
│   ├── App.tsx                  # لایه اصلی، تم روشن/تاریک و مرکز اعلان‌ها (NotificationCenter)
│   ├── components/              # کامپوننت‌های داشبورد (Investigate, Reports, Scheduled, Logs, Help و ...)
│   └── utils/                   # توابع خالص تحلیل، پارس CSV/TXT، محاسبه سهمیه و تست‌های واحد
├── tests/                       # آزمون‌های خودکار نسخه پایتون
│   └── test_soti.py
├── main.py                      # نقطه ورود نسخهٔ خط فرمان (Python CLI)
├── server.ts                    # سرور Express و APIهای بک‌اند داشبورد وب (پورت 3000)
├── index.html                   # فایل ورودی وب‌اپلیکیشن
├── requirements.txt             # وابستگی‌های پایتون
├── package.json                 # وابستگی‌ها و اسکریپت‌های Node.js / Vite
├── .env.example                 # الگوی استاندارد متغیرهای محیطی و کلیدهای API
└── README.md                    # مستندات پروژه
```

---

## ۶. اجرای آزمون‌ها (Testing)

- **آزمون‌های واحد پایتون:**
  ```bash
  python -m unittest discover -s tests
  ```

- **آزمون‌های واحد TypeScript و بررسی تایپ‌ها:**
  ```bash
  npx --yes tsx --test src/utils/*.test.ts
  npm run lint
  ```
