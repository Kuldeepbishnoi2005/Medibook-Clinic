# MediBook – An Integrated Healthcare Appointment Booking System

MediBook is a full-stack doctor appointment booking system built with **Node.js + Express** and **MySQL**.  
It supports three roles: **Patient**, **Doctor**, and **Admin**, with separate panels and features for each.

---

## ✨ Features

### 👤 Patient

- Register with **email OTP verification** (6-digit code)
- Login / Logout
- Browse doctors by specialty
- View doctor profiles & availability
- Book appointments with time-slot selection
- Cancel appointments
- View & print **appointment invoice**
- Mark doctors as **Favourites**
- Give **testimonials / feedback**

### 🩺 Doctor

- Separate **doctor login** (email + password set by admin)
- Personalized dashboard:
  - “Good morning/afternoon/evening/night, Dr. NAME”
  - Total / Upcoming / Pending appointments
  - Quick links to appointments & notes
- View own appointments with filters:
  - By status, date range, and patient search
- Add **notes & prescriptions** per appointment
- Schedule **follow-up appointments**
- View **patient medical history** (all past visits with this doctor)

### 🛡️ Admin

- Admin login (promoted from user)
- Modern admin dashboard:
  - Total patients, doctors, appointments, online revenue
  - Today / upcoming / completed appointment counts
  - Top specialties by appointment count
  - Recent appointments table
- Full control:
  - **Patients** – view & delete
  - **Doctors** – create, edit (photo, bio, availability, fee, login email/password)
  - **Appointments** – list, change status (pending/confirmed/cancelled/completed), view notes
  - **Specialties** – add/edit/delete (linked to doctors)
  - **Clinic holidays** – set closed days, prevent bookings on those dates
  - **Testimonials** – (optional; if you add admin routes)
- **Activity log / audit trail**:
  - Records key actions by admin and doctors (e.g. status change, notes update, specialty add, etc.)

---

## 🧱 Tech Stack

- **Backend**: Node.js, Express
- **Database**: MySQL
- **ORM/Driver**: `mysql2` (promise pool)
- **Views**: EJS + Bootstrap 5 + Bootstrap Icons
- **Auth & Sessions**: `express-session`, `bcryptjs`
- **Email (OTP & notifications)**: `nodemailer`
- **File Uploads**: `multer` (for doctor profile photos)
- **Security**: Basic session config, prepared statements (no SQL injection), server-side validation

---

## 📁 Project Structure

```text
project-root/
  server.js
  db.js
  package.json
  .env.example
  /views
    /partials
      header.ejs
      footer.ejs
    home.ejs
    login.ejs
    register.ejs
    forgot_password.ejs
    reset_password.ejs
    doctors.ejs
    doctor_detail.ejs
    book_appointment.ejs
    my_appointments.ejs
    favorites.ejs
    testimonials.ejs
    invoice.ejs
    doctor_dashboard.ejs
    doctor_appointments.ejs
    doctor_appointment_notes.ejs
    doctor_patient_history.ejs
    admin_dashboard.ejs
    admin_patients.ejs
    admin_doctors.ejs
    admin_doctor_form.ejs
    admin_appointments.ejs
    admin_appointment_detail.ejs
    admin_specialties.ejs
    admin_holidays.ejs
    admin_logs.ejs
  /public
    /css
      styles.css
    /uploads
      /doctors
  /db
    schema.sql               # optional: MySQL schema script
