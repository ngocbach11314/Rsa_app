# Truyền file có chữ 
Ứng dụng web hỗ trợ gửi và nhận file kèm chữ ký số RSA, đảm bảo tính xác thực và toàn vẹn dữ liệu.

## Tính năng

👤 Người gửi
  Tải lên file văn bản
  
  Sinh cặp khóa RSA (công khai/riêng tư)
  
  Tạo chữ số từ tệp
  
  Nội dung hóa mã hóa nếu cần
  
  Gửi file + chữ ký + khóa khai báo tới người nhận
  
  Cho phép tải về:
  
    -📄 Tệp gốc
  
    -🔏 Tệp chữ ký số
  
    -🔑 Khóa công khai
  
👥 Người nhận
  -Tải lên các tệp đã nhận: file văn bản, chữ ký và khóa chung
  
  -Kiểm tra ký tự bằng Flask-SocketIO
  
  -Xác minh xem nội dung đã được thay đổi hay không
  
  -Hiển thị kết quả xác thực ngay trên giao diện

## Công nghệ sử dụng
  - Frontend:
  - HTML5
  - CSS (Bootstrap 5)
  - JavaScript (Fetch API)
- Backend:
  - Python 3
  - Flask
  - RSA + SHA256 để ký hiệu và xác minh  

## Giao diện
![image](https://github.com/user-attachments/assets/ec49917c-f25d-479e-ac5d-a100c892d245)
![image](https://github.com/user-attachments/assets/b96cb2d4-25ff-4c1e-bd2e-8b4db520f8b1)


