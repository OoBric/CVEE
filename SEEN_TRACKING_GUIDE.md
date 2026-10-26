# VulnScope v1.5 — คู่มือ Mark as Seen / Updated

## วิธีใช้

1. เปิด `START_WINDOWS.bat` ตามปกติ แล้ว Search เวอร์ชันที่ต้องการ
2. ระบบยังแสดง **Version Matched** เท่านั้น และใช้ Filter Severity ตามเดิม
3. CVE ที่ยังไม่เคย Mark ในฐานข้อมูลนี้จะขึ้น `NEW` (ไม่ได้แปลว่าเพิ่งเผยแพร่วันนี้)
4. อ่าน Advisory แล้วกด `✓ Mark seen` ที่รายการหรือในหน้ารายละเอียด
5. รายการจะถูกซ่อนจากแท็บ **New / Updated** โดยยังดูได้ใน **All matched** และ **Seen**
6. เมื่อกด Search รอบใหม่แล้วรายละเอียดสำคัญของ Advisory เปลี่ยน (Description, Affected / Fixed Version, Workaround, CVSS, Severity, Last Modified, KEV เป็นต้น) รายการที่เคย Seen จะกลับเป็น `UPDATED` จนกด Mark seen อีกครั้ง
7. หากต้องการกลับมาตรวจ CVE เดิม กด `↺ Mark unread` ในแท็บ Seen
8. ปุ่ม `Mark displayed as seen` ใช้กับรายการที่มองเห็นตาม Severity / Keyword / Read Filter ณ ขณะนั้น ไม่ได้ Mark CVE อื่นที่ถูกซ่อน

## เก็บสถานะตรงไหน?

ระบบสร้าง `data/cve_tracking.sqlite3` ในโฟลเดอร์ที่แตก ZIP เมื่อเริ่มค้นหารอบแรก
สถานะจำแยกตาม Vendor + Version + Hotfix + CVE ID (เช่น Check Point R82 Take 126 และ Take 127 คนละรายการ)
SQLite เป็นไฟล์ในเครื่อง ใช้งานต่อได้เมื่อปิดหน้าเว็บ / รีสตาร์ตเซิร์ฟเวอร์ แต่ยังไม่ซิงก์กับ Microsoft Loop / เครื่องอื่นโดยอัตโนมัติ

**วิธีอัปเกรด ZIP:** ปิดเซิร์ฟเวอร์ก่อน แล้วคัดลอก `data/` จากเวอร์ชันเดิมเข้าโฟลเดอร์เวอร์ชันใหม่ อย่าคัดลอกขณะกำลังเขียนไฟล์ SQLite

**กำหนดที่เก็บถาวรบน Windows (ทางเลือก):** ก่อนเปิด `START_WINDOWS.bat` ตั้ง Environment Variable `VULNSCOPE_DB_PATH` เป็น path เต็มของไฟล์ SQLite เช่น `C:\VulnScopeData\cve_tracking.sqlite3` (ตั้ง Folder permissions ให้เขียนได้)

## การอัปเดตใหม่

- ระบบจะตรวจจับสถานะ `UPDATED` เมื่อมีการค้นหา CVE ครั้งใหม่หรือมี Watchlist Scheduler เรียก Backend ตามรอบ **ไม่ใช่ Push จาก NVD แบบ Real-time**
- ข้อมูลเปลี่ยนจาก NVD/Vendor ที่ถูกแก้ไขหลังจาก Mark Seen สามารถเปลี่ยนเป็น UPDATED ได้ แม้ยังเป็น CVE เดิม
- หากข้อมูลต้นทางไม่ครบ จะไม่ล้าง Seen history แต่ CVE ที่ไม่ถูกดึง/ไม่ Match ก็จะไม่ปรากฏในรายการ ณ การค้นหานั้น
- การเปลี่ยนรูปแบบข้อความในต้นทางหรือข้อมูลจากหลาย Feed อาจทำให้รายการขึ้น UPDATED ได้ ควรเปิด Official Advisory เพื่อยืนยัน

## Cloud deployment

การใช้ local SQLite บน Cloud Run ที่พื้นที่เก็บข้อมูลไม่ถาวรจะทำให้ประวัติหายเมื่อ instance ถูกเปลี่ยน ในอนาคตหาก Deploy บน Cloud ควรเปลี่ยนส่วนนี้เป็น PostgreSQL/Cloud SQL และใส่ Authentication ก่อนเปิดให้คนอื่นใช้

## การทดสอบ

ผ่าน Python automated tests 29 cases และ UI smoke ผ่าน Browser ด้วยข้อมูล API จำลอง ครอบคลุม NEW → SEEN → UPDATED → SEEN; ยังไม่ได้ยืนยัน CVE Live ครบทุกแหล่ง
