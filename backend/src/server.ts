import express from 'express';
import http from 'http';
import { Server as SocketIOServer} from 'socket.io';
import cors from 'cors';
import dotenv from 'dotenv';
import authRoutes from './routes/auth.routes';
import mfaRoutes from './routes/mfa.routes';
import {connectDB} from "./utils/db.util";

dotenv.config();

const app = express();
const server = http.createServer(app);

const io = new SocketIOServer(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

app.use(cors());
app.use(express.json());

app.use('/api/auth', authRoutes);
app.use('/api/mfa', mfaRoutes);

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

interface SocketUserMap {
  [userId: string]: string;
}
const onlineUsers: SocketUserMap = {};

io.on('connection', (socket) => {
  console.log(`Socket connected: ${socket.id}`);

  socket.on('register', (userId: string) => {
    onlineUsers[userId] = socket.id;
    console.log(`User registered for socket notifications: ${userId}`);
  });

  socket.on('disconnect', () => {
    for (const [userId, id] of Object.entries(onlineUsers)) {
      if (id === socket.id) delete onlineUsers[userId];
    }
    console.log(`Socket disconnected: ${socket.id}`);
  });
});

export const sendPushNotification = (userId: string, event: string, data: any) => {
  const socketId = onlineUsers[userId];
  if (socketId) {
    io.to(socketId).emit(event, data);
    console.log(`Sent push to ${userId} via socket: ${event}`);
  }
};

const PORT = process.env.PORT || 5000;
connectDB().then(() => { 

server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
})});
