const express = require("express");
const router = express.Router();

const User = require("./../models/User");

const UserVerification = require("./../models/UserVerification");

const ForgotPassword = require("./../models/ForgotPassword");

const nodemailer = require("nodemailer");

const { v4: uuidv4 } = require("uuid");

require("dotenv").config();

const bcrypt = require("bcrypt");

//static files
const path = require("path");

var transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  auth: {
    user: process.env.AUTH_EMAIL,
    pass: process.env.AUTH_PASS,
  },
  secure: false,
  tls: { rejectUnauthorized: false },
  debug: true,
});

transporter.verify((error, success) => {
  if (error) {
    console.log(error);
  } else {
    console.log("ready for messs");
    console.log(success);
  }
});

// sign-up
router.post("/signup", (req, res) => {
  let { email, password, password2 } = req.body;
  email = email.trim();
  password = password.trim();
  password2 = password2.trim();

  if (email == "" || password == "" || password2 == "") {
    res.json({
      status: "FAILED",
      message: "Empty input fields!",
    });
  } else if (
    /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(email.value)
  ) {
    res.json({
      status: "FAILED",
      message: "Invalid email entered!",
    });
  } else if (password != password2) {
    res.json({
      status: "FAILED",
      message: "Passwords do not match",
    });
  } else if (password.length < 8 || password2.length < 8) {
    res.json({
      status: "FAILED",
      message: "Password is too short!",
    });
  } else {
    User.find({ email })
      .then((result) => {
        if (result.length) {
          res.json({
            status: "FAILED",
            message: "User email already exists",
          });
        } else {
          // Passowrd handling
          const saltRounds = 10;
          bcrypt
            .hash(password, saltRounds)
            .then((hashedPassword) => {
              const newUser = new User({
                email,
                password: hashedPassword,
                verified: false,
              });

              newUser
                .save()
                .then((result) => {
                  // account verification
                  sendVerificationEmail(result, res);
                })
                .catch((err) => {
                  res.json({
                    status: "FAILED",
                    message: "An error occurred while saving user account",
                  });
                });
            })
            .catch((err) => {
              res.json({
                status: "FAILED",
                message: "An error occured while hashing password",
              });
            });
        }
      })
      .catch((err) => {
        console.log(err);
        res.json({
          status: "FAILED",
          message: "An error occured while checking for existing user!",
        });
      });
  }
});

// verification
const sendVerificationEmail = ({ _id, email }, res) => {
  // change url when in production
  const currentUrl = process.env.WEB_NAME;

  const uniqueString = uuidv4() + _id;

  //mail option
  const mailOptions = {
    from: process.env.AUTH_EMAIL,
    to: email,
    subject: "Verify your email",
    html: `<p>Verify your email address to complete the signup and login process.</p> <p>This link <b>expires in 6 hours</b>.</p><p> Use <a href=${
      currentUrl + "user/verify/" + _id + "/" + uniqueString
    }>link</a> to proceed </p>`,
  };

  const saltRounds = 10;
  bcrypt
    .hash(uniqueString, saltRounds)
    .then((hashedUniqueString) => {
      const newVerification = new UserVerification({
        userId: _id,
        uniqueString: hashedUniqueString,
        createdAt: Date.now(),
        expiresAt: Date.now() + 21600000,
      });

      newVerification
        .save()
        .then(() => {
          transporter
            .sendMail(mailOptions)
            .then(() => {
              //email sent and verification saved
              res.json({
                status: "PENDING",
                message: "Verification email sent",
              });
            })
            .catch((error) => {
              console.log(error);
              res.json({
                status: "FAILED",
                message: "Verification email failed",
              });
            });
        })
        .catch((error) => {
          console.log(error);
          res.json({
            status: "FAILED",
            message: "Couldn't save verification email detail",
          });
        });
    })
    .catch(() => {
      res.json({
        status: "FAILED",
        message: "An error occurred while hashing email details",
      });
    });
};

// verify email
router.get("/verify/:userId/:uniqueString", (req, res) => {
  let { userId, uniqueString } = req.params;

  UserVerification.find({ userId })
    .then((result) => {
      if (result.length > 0) {
        //user verification record exists
        const { expiresAt } = result[0];
        const hashedUniqueString = result[0].uniqueString;

        if (expiresAt < Date.now()) {
          UserVerification.deleteOne({ userId })
            .then((result) => {
              User.deleteOne({ _id: userId })
                .then(() => {
                  let message = "Link has expired. Please sign up again";
                  res.redirect(`/user/verified/error=true&message=${message}`);
                })
                .catch((error) => {
                  let message =
                    "Clearing user with expired unique string failed";
                  res.redirect(`/user/verified/error=true&message=${message}`);
                });
            })
            .catch((error) => {
              console.log(error);
              let message =
                "An error occurred while clearing expired user verification record";
              res.redirect(`/user/verified/error=true&message=${message}`);
            });
        } else {
          // valid record exists
          bcrypt
            .compare(uniqueString, hashedUniqueString)
            .then((result) => {
              if (result) {
                User.updateOne({ _id: userId }, { verified: true })
                  .then(() => {
                    UserVerification.deleteOne({ userId })
                      .then(() => {
                        res.sendFile(
                          path.join(__dirname, "./../views/verified.html")
                        );
                      })
                      .catch((error) => {
                        console.log(error);
                        let message =
                          "An error occurred while finalizing successful verification";
                        res.redirect(
                          `/user/verified/error=true&message=${message}`
                        );
                      });
                  })
                  .catch((error) => {
                    console.log(error);
                    let message =
                      "An error occurred while updating user record to show verified";
                    res.redirect(
                      `/user/verified/error=true&message=${message}`
                    );
                  });
              } else {
                let message =
                  "Invalid verification details passed. check your inbox";
                res.redirect(`/user/verified/error=true&message=${message}`);
              }
            })
            .catch((error) => {
              let message = "An error occurred while comparing unique strings";
              res.redirect(`/user/verified/error=true&message=${message}`);
            });
        }
      } else {
        let message =
          "Account record doesn't exist or has been verified already. Please sign up or log in";
        res.redirect(`/user/verified/error=true&message=${message}`);
      }
    })
    .catch((error) => {
      console.log(error);
      let message =
        "An error occurred while checking for existing user verification record";
      res.redirect(`/user/verified/error=true&message=${message}`);
    });
});

// verified page route
router.get("/verified", (req, res) => {
  res.sendFile(path.join(__dirname, "./../views/verified.html"));
});

// signin
router.post("/signin", (req, res) => {
  let { email, password } = req.body;
  email = email.trim();
  password = password.trim();

  if (email == "" || password == "") {
    res.json({
      status: "FAILED",
      message: "Empty input fields",
    });
  } else {
    // check if user exist
    User.find({ email })
      .then((data) => {
        if (data.length) {
          // check if user is verified
          if (!data[0].verified) {
            res.json({
              status: "FAILED",
              message: "Email hasn't been verified yet. check your inbox",
            });
          } else {
            const hashedPassword = data[0].password;
            bcrypt
              .compare(password, hashedPassword)
              .then((result) => {
                if (result) {
                  res.json({
                    status: "SUCCESS",
                    message: "Signin Successful",
                    data: data,
                  });
                } else {
                  res.json({
                    status: "FAILED",
                    message: "Invalid password entered",
                  });
                }
              })
              .catch((err) => {
                res.json({
                  status: "FAILED",
                  message: "An error occurred while comparing password",
                });
              });
          }
        } else {
          res.json({
            status: "FAILED",
            message: "Invalid credentials entered!",
          });
        }
      })
      .catch((err) => {
        res.json({
          status: "FAILED",
          message: "An error occurred while checking for existing user!",
        });
      });
  }
});

// forgot password
router.post("/forgotPassword", (req, res) => {
  const { email, redirectUrl} = req.body;

  User
    .find({email})
    .then((data) => {
      if (data.length) {
        // user exists

        // check user verification
        if (!data[0].verified) {
          res.json({
            status: "FAILED",
            message: "Email hasn't been verified yet. check your inbox",
          });
        } else {
          // proceed with email reset
          sendResetEmail(data[0], redirectUrl, res);
        }
      } else {
        res.json({
          status: "FAILED",
          message: "No account with the email exists",
        });
      }
    })
    .catch(error => {
    console.log(error);
    res.json({
      status: "FAILED",
      message: "An error occurred while checking for existing user!",
    });
  })
})

//send password email
const sendResetEmail = ({_id, email}, redirectUrl, res) => {
  const resetString = uuidv4() + _id;

  ForgotPassword
    .deleteMany({ userId: _id})
    .then(result => {

      const mailOptions = {
        from: process.env.AUTH_EMAIL,
        to: email,
        subject: "Password Reset",
        html: `<p>Lost password?</p> <p>Don't worry, use the link below to reset your password</p> <p>This link <b>expires in 6 hours</b>.</p><p> Use <a href=${
          redirectUrl + "/" + _id + "/" + resetString
        }>link</a> to proceed </p>`,
      };

      const saltRounds = 10;
      bcrypt
        .hash(resetString, saltRounds)
        .then(hashedResetString => {
          const newForgotPassword = new ForgotPassword({
            userId: _id,
            resetString: hashedResetString,
            createdAt: Date.now(),
            expiresAt: Date.now() + 3600000
          });

          newForgotPassword
            .save()
            .then(() => {
              transporter
                .sendMail(mailOptions)
                .then(() => {
                  res.json({
                    status: "PENDING",
                    message: "Password reset email sent",
                  });
                })
                .catch(error => {
                  console.log(error);
                  res.json({
                    status: "FAILED",
                    message: "Password reset email failed",
                  });
                })
            })
            .catch(error => {
              console.log(error);
              res.json({
                status: "FAILED",
                message: "Couldn't save password reset data!",
              });
            })
        })
        .catch(error => {
          console.log(error);
          res.json({
            status: "FAILED",
            message: "An error occurred while hashing the password reset data!",
          });
        })
    })
    .catch(error => {
      console.log(error);
      res.json({
        status: "FAILED",
        message: "Clearing existing password reset records failed",
      });
    })
}

//update password
router.post("/updatePassword", (req, res) => {
  const { userId, resetString, newPassword, confirmPassword } = req.body;

  ForgotPassword.find({userId})
    .then(result => {
      if (result.length > 0) {

        if (newPassword != confirmPassword) {
          res.json({
            status: "FAILED",
            message: "Passwords do not match",
          })
         }
        

        const { expiresAt } = result[0];
        const hashedResetString = result[0].resetString
        if(expiresAt < Date.now()) {
          ForgotPassword
            .deleteOne({userId})
            .then(() => {
              res.json({
                status: "FAILED",
                message: "Password reset link has expired",
              });
            })
            .catch(error => {
              console.log(error);
              res.json({
                status: "FAILED",
                message: "Clearing password records failed.",
              });
            })
        } else {
          bcrypt
            .compare(resetString, hashedResetString)
            .then((result) => {
              if (result) {
                const saltRounds = 10
                bcrypt
                  .hash(newPassword, saltRounds)
                  .then(hashedNewPassword => {
                    User.updateOne({_id: userId}, {password: hashedNewPassword})
                      .then(() => {
                        ForgotPassword.deleteOne({userId})
                        .then(() => {
                          res.json({
                            status: "SUCCESS",
                            message: "Password reset successful.",
                          });
                        })
                        .catch(error => {
                          res.json({
                            status: "FAILED",
                            message: "An error occured while finalising reset password.",
                          });
                        })
                      })
                      .catch(error => {
                        console.log(error);
                        res.json({
                          status: "FAILED",
                          message: "Updating user password failed.",
                        });
                      })
                  })
                  .catch(error => {
                    console.log(error);
                    res.json({
                      status: "FAILED",
                      message: "An error occurred while hashing new password",
                    });
                  })
              }  else {
                res.json({
                  status: "FAILED",
                  message: "invalid password reset details passed",
                });
              }
            })
            .catch(error => {
              res.json({
                status: "FAILED",
                message: "Password reset string failed.",
              });
            })
        }

      } else {
        res.json({
          status: "FAILED",
          message: "Password reset request not found.",
        });
      }
    })
    .catch(error => {
      console.log(error)
      res.json({
        status: "FAILED",
        message: "Checking for existing password reset record failed.",
      });
    })
})

module.exports = router;
