import { Server, Socket } from 'socket.io';

export const initSockets = (io: Server) => {
  io.on('connection', (socket: Socket) => {
    console.log(`🔌 Socket connected: ${socket.id}`);

    socket.on('disconnect', () => {
      console.log(`❌ Socket disconnected: ${socket.id}`);
    });

    socket.on('security:event', (data) => {
      console.log('⚠️ Security Event:', data);
      io.emit('security:update', data);
    });
  });
};
