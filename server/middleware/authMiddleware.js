import jwt from "jsonwebtoken";

const authMiddleware = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                message: "Authorization token missing or invalid"
            });
        }

        const token = authHeader.split(" ")[1];

        if (!token) {
            return res.status(401).json({
                message: "Authorization token missing or invalid"
            });
        }

        if (!process.env.JWT_SECRET) {
            return res.status(500).json({
                message: "Server configuration error"
            });
        }

        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET,
            {
                algorithms: ["HS256"]
            }
        );

        if (
            typeof decoded !== "object" ||
            decoded === null ||
            typeof decoded.userId !== "string" ||
            !decoded.userId
        ) {
            return res.status(401).json({
                message: "Invalid token"
            });
        }

        req.user = {
            id: decoded.userId
        };

        return next();

    } catch (error) {
        return res.status(401).json({
            message: "Invalid or expired token"
        });
    }
};

export default authMiddleware;