<?php
namespace App\Services;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

class Mailer
{
    protected $mailer;

    public function __construct()
    {
        $this->mailer = new PHPMailer(true);
        $this->mailer->SMTPDebug = SMTP::DEBUG_OFF;
        $this->mailer->isSMTP();
        $this->mailer->Host = 'smtp.gmail.com';
        $this->mailer->SMTPAuth = true;
        $this->mailer->Username = 'your_email@gmail.com'; // Replace with your Gmail email address
        $this->mailer->Password = 'your_gmail_password'; // Replace with your Gmail password
        $this->mailer->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $this->mailer->Port = 587;
    }

    public function sendVerificationEmail($user)
    {
        $this->mailer->isHTML(true);
        $this->mailer->Subject = 'Verify your account';
        $this->mailer->Body = 'Click the following link to verify your account: ' . $_SERVER['HTTP_HOST'] . '/auth?action=verify&token=' . $user->getVerificationToken();
        $this->mailer->addAddress($user->getEmail(), $user->getEmail());
        $this->mailer->send();
    }
}
?>
