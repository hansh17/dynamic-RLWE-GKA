dynamic version

- constant-time 삭제
- 용량 문제상 augmented_pub_key (peer 0)에서 sigma2 대신 sigma1로부터 랜덤 샘플링함 (augmented pub key 계산시 peer 0의 경우 "시그마 2로부터 샘플링한다"라고 주석에 써놓음)
- rlwe.c에서 random table2에 관한 부분 다 주석처리 되어있음. 이거 해제해야함.
- random table2는 업로드 안함 (이전에 말했던 폴더에 저장해놓음)
- join algorithm에서 peer 1의 secret key를 peer 2~N-2에게 전달함. 여기서 이론이랑 일치시키려면 
secret key를 session key로 바꿀 수 있음. 내가 생각한 안은 session key가 현재 128 hexadecimal인데, bit로 표현하면 512bit가 됨. 
이거를 복사해서 concatenation하면 1024-bit로 쓸 수 있을 듯. 우리는 세션 키 저장 따로 안하니까, 임의의 1024-bit 생성해서 쓰면 될듯. 
(bit는 0,1밖에 안되므로 무조건 1024-dim을 가진 R_q에서 작은 시그마값으로 샘플링 한거일 수 밖에 없음)
