import express, { Request, Response } from "express";
import jwt from "jsonwebtoken";

const app = express();
const port = 5001;

// DB 예시
const user = {
  email: "jwt@email.com",
  password: "1234",
  name: "kim",
};

const ACCESS_SECRET_KEY = "access_secret_key";
const REFRESH_SECRET_KEY = "refresh_secret_key";

// 로그인 라우트
app.post("/login", (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (user.email !== email) {
    res.status(403).json("This email does not exist.");
  }

  if (user.password !== password) {
    res.status(403).json("Password is not valid.");
  }

  //로그인 성공시, access token과 refresh token 생성
  try {
    const accessToken = jwt.sign(
      {
        email: user.email,
        name: user.name,
      },
      ACCESS_SECRET_KEY,
      {
        expiresIn: "1h",
        issuer: "access issuer",
      }
    );

    const refreshToken = jwt.sign(
      {
        email: user.email,
        name: user.email,
      },
      REFRESH_SECRET_KEY,
      {
        expiresIn: "24h",
        issuer: "refresh issuer",
      }
    );

    res.cookie("accessToken", accessToken, {
      secure: true,
      httpOnly: true,
    });

    res.cookie("refreshToken", refreshToken, {
      secure: true,
      httpOnly: true,
    });

    res.status(200).json("login success");
  } catch {
    res.status(500).json("login failed");
  }
});

// 로그아웃 라우트
app.get("/logout", (req: Request, res: Response) => {
  try {
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");

    res.status(200).json("Logout Success");
  } catch (error) {
    res.status(500).json(error);
  }
});

// access token payload 반환 라우터
app.get("/authentication", (req: Request, res: Response) => {
  try {
    const token = req.cookies.accessToken;
    if (!token) {
      return res.status(401).json("Access Token not found"); // 토큰이 없을 경우 처리
    }

    const data = jwt.verify(token, ACCESS_SECRET_KEY);

    res.status(200).json(data);
  } catch (error) {
    res.status(500).json(error);
  }
});

// access token 재발급 라우터
app.get("/access-token-reissue", (req: Request, res: Response) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      return res.status(401).json("Refresh Token not found"); // refreshToken이 없을 경우 처리
    }

    const data = jwt.verify(refreshToken, REFRESH_SECRET_KEY);

    const accessToken = jwt.sign(
      {
        email: user.email,
        name: user.name,
      },
      ACCESS_SECRET_KEY,
      {
        expiresIn: "1m",
        issuer: "access issuer",
      }
    );

    res.cookie("accessToken", accessToken, {
      secure: false,
      httpOnly: true,
    });

    res.status(200).json("Access Token Recreated");
  } catch (error) {
    res.status(500).json(error);
  }
});

//서버 시작
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
