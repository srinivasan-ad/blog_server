import express, { NextFunction } from 'express';
import cors from 'cors'
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv'; 
dotenv.config();
import {Pool} from 'pg'
const app : express.Application = express();
app.use(
    cors({
      origin: "http://localhost:3000", 
      credentials: true,
    })
  );
app.use(cookieParser())

app.use(express.json());
const pool = new Pool({connectionString : process.env.DATABASE_URL})
//   const client = pool.connect()
//   .then(client => {
//       console.log("Connected to database");
//       client.release();
//   })
//   .catch(err => console.error("Database connection failed", err));


  async function CheckTokenValidity(req: any, res: any, next: any): Promise<any> {
    const token = req.cookies?.authToken;

    if (!token) {
        return res.status(401).json({ isValid: false, message: "No token provided!" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY as string) as jwt.JwtPayload & { id: number };

        const result = await pool.query('SELECT id FROM Users WHERE id = $1;', [decoded.id]);

        if (result.rows.length === 0) {
            return res.status(401).json({ isValid: false, message: "Invalid token!" });
        }

        req.body.userId = decoded.id; 
        return next();
    } catch (e) {
        console.error("JWT Error:", e);
        return res.status(401).json({ isValid: false, message: "Token expired or invalid!" });
    }
}

app.get('/hello', (req, res) => {
    try {
        res.send("Hello champ!");
    } catch (e) {
        console.error(e);
    }
});


app.get('/user/validate', async (req, res)  : Promise<any> => {
    const token = req.cookies?.authToken;

    if (!token) {
        return res.status(401).json({ isValid: false, message: "No token provided" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY as string) as jwt.JwtPayload & { id: number };
        const result = await pool.query('SELECT * FROM Users WHERE id = $1;', [decoded.id]);

        if (result.rows.length === 0) {
            return res.status(401).json({ isValid: false, message: "Invalid token" });
        }

        return res.status(200).json({ isValid: true, user: result.rows[0] });
    } catch (error) {
        return res.status(401).json({ isValid: false, message: "Token expired or invalid" });
    }
});


app.post('/user/signup', async (req, res) : Promise<any> => {
    const { name, username, password } = req.body;

    try {
        const selectResult = await pool.query('SELECT * FROM Users WHERE username = $1;', [username]);

        if (selectResult.rows.length > 0) {
            return res.status(400).json({ success: false, exist: true, message: 'Username is already taken' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const insertQuery = 'INSERT INTO Users(name, username, password) VALUES($1, $2, $3) RETURNING id;';
        const insertResult = await pool.query(insertQuery, [name, username, hashedPassword]);

        if (insertResult.rowCount === 0) {
            return res.status(401).json({ success: false, message: 'User registration failed' });
        }

        const token = jwt.sign({ id: insertResult.rows[0].id }, process.env.JWT_SECRET_KEY as string, { expiresIn: "5m" });

        res.cookie("authToken", token, {
            httpOnly: true,
            secure:false,
            sameSite : 'lax',
            maxAge: 5 * 60 * 1000
        });

        return res.status(200).json({ success: true, message: 'User registered successfully' });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ success: false, error: "Internal Server Error" });
    }
});


app.post('/user/signin', async (req, res) : Promise<any> => {
    const { username, password } = req.body;

    try {
        const selectResult = await pool.query('SELECT * FROM Users WHERE username = $1;', [username]);

        if (selectResult.rows.length === 0) {
            return res.status(404).json({ message: 'Username is incorrect' });
        }

        const hashedPassword = selectResult.rows[0].password;
        const isValidPass = await bcrypt.compare(password, hashedPassword);

        if (!isValidPass) {
            return res.status(405).json({ message: 'Password is incorrect' });
        }

        const token = jwt.sign({ id: selectResult.rows[0].id }, process.env.JWT_SECRET_KEY as string, { expiresIn: "5m" });

        res.cookie("authToken", token, {
            httpOnly: true,
            domain: "localhost",
            secure: false,
            sameSite : 'lax',
            maxAge: 5 * 60 * 1000
        });
        console.log('Set-Cookie Header Sent:', res.getHeaders()['set-cookie']);

        return res.status(200).json({ message: 'Logged in successfully' });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ message: "Internal Server Error" });
    }
});


app.post('/user/blog', async (req, res): Promise<any> => {
    const { title, content, published, userId } = req.body;
    const client = await pool.connect();
    if (!title || !content || typeof published !== "boolean" || !userId) {
        return res.status(400).json({ success: false, message: "Missing required fields." });
      }
      
    try {
        const checkUser = await client.query('SELECT id FROM Users WHERE id = $1;', [userId]);
        if (checkUser.rows.length === 0) {
          return res.status(404).json({ success: false, message: "User not found." });
        }
      
        await client.query('BEGIN');
        
        const insertQuery = 'INSERT INTO Blogs (author_id, title, content, published) VALUES ($1, $2, $3, $4) RETURNING id;';
        const insertResult = await client.query(insertQuery, [userId, title, content, published]);
      
        await client.query('COMMIT');
      
        return res.status(201).json({ blog: insertResult.rows[0] });
      } catch (e) {
        await client.query('ROLLBACK');
        console.error("Error posting blog:", e);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
      }})
  

  app.put('/user/blog', async (req, res): Promise<any> => {
    const { title, content, blogId, userId } = req.body;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const checkResult = await client.query(
        'SELECT * FROM Blogs WHERE id = $1 AND author_id = $2;',
        [blogId, userId]
      );
  
      if (checkResult.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ success: false, message: "Blog not found or unauthorized." });
      }
      const updateQuery = 'UPDATE Blogs SET title = $1, content = $2 WHERE id = $3 RETURNING *;';
      const updateResult = await client.query(updateQuery, [title, content, blogId]);
  
      await client.query('COMMIT');
  
      return res.status(200).json({blog: updateResult.rows[0] });
  
    } catch (e) {
      await client.query('ROLLBACK');
      console.error("Error updating blog:", e);
      return res.status(500).json({ success: false, message: "Internal Server Error" });
    } finally {
      client.release();
    }
  });
  

app.get('/user/blog',  async (req, res): Promise<any> => {
    const { page } = req.query;
    const pageSize = 4;
    const pageNumber = parseInt(page as string) || 1;
    const offset = (pageNumber - 1) * pageSize;
  
    try {
      const result = await pool.query(
        `SELECT Blogs.id, Blogs.title, substring(Blogs.content from 1 for 100) AS content, Blogs.published, Blogs.created_at, 
                Users.name AS author_name
         FROM Blogs 
         JOIN Users ON Blogs.author_id = Users.id 
         ORDER BY Blogs.created_at DESC 
         LIMIT $1 OFFSET $2;`,
        [pageSize, offset]
      );
  
      return res.status(200).json({ blogs: result.rows });
    } catch (e) {
      console.error("Error fetching all blogs:", e)
      return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
  });
  
app.get('/user/blog/:id', async (req, res) : Promise<any> => {
    const { id } = req.params;

    try {
        const selectQuery = `SELECT Blogs.id, Blogs.title, 
       Blogs.content, Blogs.published, Blogs.created_at, 
       Users.name AS author_name FROM Blogs JOIN 
       Users ON Blogs.author_id = Users.id
       WHERE Blogs.id = $1;`

        const result = await pool.query(selectQuery, [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: "Blog not found" });
        }

        return res.status(200).json({blog: result.rows[0] });
    } catch (e) {
        console.error("Error fetching blog:", e);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});

app.listen(process.env.PORT,() => 
{
    console.log(`Server ntarted at http://localhost:${process.env.PORT}`);
})