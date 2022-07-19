const mongoose = require("mongoose");
const { appError, handleErrorAsync } = require("../utils/errorHandler");
const getHttpResponse = require("../utils/successHandler");
const bcrypt = require("bcryptjs");
const validator = require("validator");
const { generateJwtToken } = require("../middleware/auth");
const User = require("../models/userModel");
const Validator = require("../utils/validator");

const nodemailer = require("nodemailer");

const users = {
  signUpCheck: handleErrorAsync(async(req, res, next) => {
    const validatorResult = Validator.signUpCheck(req.body);
    if (!validatorResult.status) {
      return next(appError(400, "40001", validatorResult.msg));
    }
    const { email } = req.body;
    const user = await User.find({ email });
    if (user.length > 0) {
      return next(appError(400, "40002", "已註冊此用戶"));
    }
    res.status(201).json(getHttpResponse({
      message: "驗證成功"
    }));
  }),
  signUp: handleErrorAsync(async(req, res, next) => {
    const validatorResult = Validator.signUp(req.body);
    if (!validatorResult.status) {
      return next(appError(400, "40001", validatorResult.msg));
    }
    password = await bcrypt.hash(req.body.password, 12);
    const { nickName, email } = req.body;
    let newUser = {};
    try {
      newUser = await User.create({
        nickName,
        email,
        password
      });
    } catch (error) {
      if (error.code === 11000) {
        return next(appError(400, "40011", "已註冊此用戶"));
      }
      return next(appError(400, "40005", "不明原因錯誤"));
    }

    const { _id } = newUser;
    const token = await generateJwtToken(_id);
    if (token.length === 0) {
      return next(appError(400, "40003", "token 建立失敗"));
    }
    const data = {
      token,
      "id": _id
    };
    res.status(201).json(getHttpResponse({
      data
    }));
  }),
  signIn: handleErrorAsync(async(req, res, next) => {
    const validatorResult = Validator.signIn(req.body);
    if (!validatorResult.status) {
      return next(appError(400, "40001", validatorResult.msg));
    }
    const { email, password } = req.body;
    const user = await User.findOne({
      email
    }).select("+password");
    if (!user) {
      return next(appError(400, "40010", "尚未註冊"));
    }
    const auth = await bcrypt.compare(password, user.password);
    if (!auth) {
      return next(appError(400, "40002", "您的密碼不正確"));
    }
    const { _id } = user;
    console.log(_id);
    const token = await generateJwtToken(_id);
    console.log(token);
    if (token.length === 0) {
      return next(appError(400, "40003", "token 建立失敗"));
    }
    const data = {
      token,
      "id": _id
    };
    res.status(201).json(getHttpResponse({
      data
    }));
  }),
  updatePassword: handleErrorAsync(async(req, res, next) => {
    const {
      user,
      body: {
        password,
        confirmPassword,
        oldPassword
      },
    } = req;
    const validatorResult = Validator.updatePw({
      password,
      confirmPassword,
      oldPassword
    });
    if (!validatorResult.status) {
      return next(appError(400, "40001", validatorResult.msg, next));
    }
    const users = await User.findOne({
      _id: user._id
    }).select("+password");
    const compare = await bcrypt.compare(oldPassword, users.password);
    if (!compare) {
      return next(appError(400, "40002", "您的舊密碼不正確!"));
    }

    users.password = null;
    const newPassword = await bcrypt.hash(req.body.password, 12);
    await User.updateOne({
      _id: user._id
    }, {
      password: newPassword
    });
    res.status(201).json(getHttpResponse({
      message: "更新密碼成功"
    }));
  }),
  getMyProfile: handleErrorAsync(async(req, res) => {
    const { user } = req;
    const profile = await User.findById(user._id).select("-logicDeleteFlag");
    res.status(200).json(getHttpResponse({
      data: profile
    }));
  }),
  getOtherProfile: handleErrorAsync(async(req, res, next) => {
    const { userId } = req.params;
    if (!(userId && mongoose.Types.ObjectId.isValid(userId))) {
      return next(appError(400, "格式錯誤", "欄位未填寫正確"));
    }
    const profile = await User.findById(userId).select("-logicDeleteFlag");
    res.status(200).json(getHttpResponse({
      data: profile
    }));
  }),
  updateProfile: handleErrorAsync(async(req, res, next) => {
    const {
      user,
      params: { userId },
      body: {
        nickName,
        gender,
        avatar
      }
    } = req;
    if (String(user._id) !== String(userId)) {
      return next(appError(400, "40004", "您無權限修改他人資料"));
    };
    if (!nickName || nickName.trim().length === 0) {
      return next(appError(400, "40001", "請填寫暱稱"));
    };
    if (avatar && !validator.isURL(avatar, { protocols: ["https"] }))
      return next(appError(400, "40001", "圖片格式不正確!"));
    const profile = await User.findByIdAndUpdate(userId, {
      nickName,
      gender,
      avatar
    }, {
      new: true
    }).select("-logicDeleteFlag");
    res.status(201).json(getHttpResponse({
      data: profile
    }));
  }),
  forgetPassword: handleErrorAsync(async(req, res, next) => {
    const { email } = req.body; // 使用者信箱

    if (email === "") {
      return next(appError(400, "40010", "欄位未填寫正確"));
    }

    const isEmailValid = validator.isEmail(email.trim());
    if (!isEmailValid) return next(appError(400, "40001", "Email 格式錯誤"));

    const user = User.findOne({email}).select("+password");
    if(!user) {
      return next(appError(400, "40010", "尚未註冊"));
    }

    // 產生一組臨時身分證 (token)
    const { _id } = user;
    const token = await generateJwtToken(_id);
    if (token.length === 0) {
      return next(appError(400, "40003", "token 建立失敗"));
    }

    // 產生隨機密碼
    const newPassword = Math.random().toString(36).substring(7);
    
    // 密碼加密
    const hashPassword = await bcrypt.hash(newPassword, 12);
    await User.updateOne(
      {
        _id: user._id
      },
      {
        password: hashPassword
      }
    );

    // 提供登入頁面網址
    const postUrl = process.env.FRONTEND_REDIRECT_URL;


    // 創建 Nodemailer 傳輸 - 寄信到用戶信箱
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    const mailOptions = {
      from: process.env.EMAIL_USER, // 自己的信箱
      to: email, // 用戶的信箱 email process.env.EMAIL_USER
      subject: "Link to Reset Password", // 主旨
      text: 
      "You are receving this because you have requested the reset of the password for your account. \n\n" +
      "Please click on the following link, or paste this into your browser to complete of receing it: \n\n" +
      `${postUrl} \n\n` + 
      "Temporary Password: \n\n" +
      `${newPassword} \n\n` +
      "If you didn't request this, please contact us. \n"
      ,
    };

    transporter.sendMail(mailOptions, (err, responses) => {
      if(err) {
        return next(appError(500, "500", "操作失敗"));
      } else {
        res.status(201).json(
          getHttpResponse({
            message: "請至 Email 查收信件"
          })
        );
      }
    });
  })
};

module.exports = users;