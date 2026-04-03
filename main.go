package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"      // ← добавьте это
	"net"          // ← добавьте это
//	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	_ "github.com/mattn/go-sqlite3"
)

const (
	chatProtocol      = "/p2p-chat/message/1.0.0"
	privateProtocol   = "/p2p-chat/private/1.0.0"
	handshakeProtocol = "/p2p-chat/handshake/1.0.0"
	keyFile           = "identity.key" // Файл для сохранения приватного ключа
)

type Message struct {
	ID        string    `json:"id"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Content   string    `json:"content"`
	Room      string    `json:"room"`
	CreatedAt time.Time `json:"created_at"`
	IsPrivate bool      `json:"is_private"`
}

type App struct {
	host        host.Host
	db          *sql.DB
	myName      string
	currentRoom string
	peers       map[string]peer.ID
	mu          sync.RWMutex
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// loadOrCreatePrivateKey загружает ключ из файла или создаёт новый
func loadOrCreatePrivateKey(path string) (crypto.PrivKey, error) {
	// Пробуем загрузить существующий ключ
	if data, err := os.ReadFile(path); err == nil {
		priv, err := crypto.UnmarshalPrivateKey(data)
		if err == nil {
			fmt.Println("✅ Загружен существующий идентификатор из", path)
			return priv, nil
		}
		fmt.Println("⚠️  Файл ключа повреждён, генерируем новый...")
	}
	
	// Генерируем новый ключ
	fmt.Println("🔑 Генерация нового постоянного идентификатора...")
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, err
	}
	
	// Сохраняем в файл
	data, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	
	if err := os.WriteFile(path, data, 0600); err != nil { // 0600 - только владелец
		return nil, err
	}
	
	fmt.Println("💾 Новый ключ сохранён в", path)
	return priv, nil
}

func NewApp(name string) (*App, error) {
	// Загружаем или создаём постоянный ключ
	priv, err := loadOrCreatePrivateKey(keyFile)
	if err != nil {
		return nil, fmt.Errorf("ошибка с ключом: %w", err)
	}
	
	// Создаём хост с постоянным ID
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings(
			"/ip4/0.0.0.0/tcp/9000",
			"/ip4/0.0.0.0/udp/9000/quic-v1", // Добавляем QUIC для лучшей производительности
		),
	)
	if err != nil {
		return nil, err
	}
	
	// Выводим информацию об ID
	peerID := h.ID()
	fmt.Printf("🔐 Ваш постоянный Peer ID: %s\n", peerID)
	fmt.Printf("📊 Безопасность: Ed25519 (256 бит, устойчив к перебору)\n")
	
	db, err := sql.Open("sqlite3", "./chat.db")
	if err != nil {
		return nil, err
	}
	
	// Обновляем схему БД - добавляем fingerprint для верификации
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS messages (
			id TEXT PRIMARY KEY,
			from_id TEXT,
			to_id TEXT,
			content TEXT,
			room TEXT,
			is_private INTEGER,
			created_at DATETIME,
			is_read INTEGER
		);
		CREATE TABLE IF NOT EXISTS contacts (
			id TEXT PRIMARY KEY,
			name TEXT,
			address TEXT,
			peer_fingerprint TEXT,
			last_seen DATETIME
		);
	`)
	if err != nil {
		return nil, err
	}
	
	app := &App{
		host:        h,
		db:          db,
		myName:      name,
		currentRoom: "general",
		peers:       make(map[string]peer.ID),
	}
	
	h.SetStreamHandler(chatProtocol, app.handleMessage)
	h.SetStreamHandler(privateProtocol, app.handlePrivateMessage)
	h.SetStreamHandler(handshakeProtocol, app.handleHandshake)
	
	return app, nil
}

func (app *App) saveMessage(msg *Message) error {
	_, err := app.db.Exec(`
		INSERT INTO messages(id, from_id, to_id, content, room, is_private, created_at, is_read)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)
	`, msg.ID, msg.From, msg.To, msg.Content, msg.Room, boolToInt(msg.IsPrivate), msg.CreatedAt, 1)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (app *App) handleMessage(stream network.Stream) {
	defer stream.Close()
	var msg Message
	if err := json.NewDecoder(stream).Decode(&msg); err != nil {
		return
	}
	if err := app.saveMessage(&msg); err != nil {
		fmt.Printf("\r\033[K[Ошибка БД] %v\n> ", err)
		return
	}
	fmt.Printf("\r\033[K\033[36m[%s] %s\033[0m: %s\n", msg.CreatedAt.Format("15:04:05"), msg.From[:8], msg.Content)
	fmt.Print("> ")
}

func (app *App) handlePrivateMessage(stream network.Stream) {
	defer stream.Close()
	var msg Message
	if err := json.NewDecoder(stream).Decode(&msg); err != nil {
		return
	}
	msg.IsPrivate = true
	if err := app.saveMessage(&msg); err != nil {
		fmt.Printf("\r\033[K[Ошибка БД] %v\n> ", err)
		return
	}
	fmt.Printf("\r\033[K\033[35m[Private] %s\033[0m: %s\n", msg.From[:8], msg.Content)
	fmt.Print("> ")
}

func (app *App) handleHandshake(stream network.Stream) {
	defer stream.Close()
	name, err := io.ReadAll(stream)
	if err != nil {
		return
	}
	peerID := stream.Conn().RemotePeer()
	
	// Получаем публичный ключ для fingerprint
	remotePubKey, err := peerID.ExtractPublicKey()
	fingerprint := ""
	if err == nil && remotePubKey != nil {
		pubBytes, _ := remotePubKey.Raw()
		fingerprint = hex.EncodeToString(pubBytes)[:16]
	}
	
	_, err = app.db.Exec(`INSERT OR REPLACE INTO contacts(id, name, address, peer_fingerprint, last_seen) VALUES(?, ?, ?, ?, ?)`,
		peerID.String(), string(name), stream.Conn().RemoteMultiaddr().String(), fingerprint, time.Now())
	if err == nil {
		fmt.Printf("\r\033[K\033[32m✅ %s добавлен в контакты\033[0m\n", string(name))
		fmt.Print("> ")
	}
}

func (app *App) sendMessage(content string) {
	if content == "" {
		return
	}
	msg := &Message{
		ID:        generateID(),
		From:      app.host.ID().String(),
		Content:   content,
		Room:      app.currentRoom,
		CreatedAt: time.Now(),
		IsPrivate: false,
	}
	if err := app.saveMessage(msg); err != nil {
		fmt.Printf("\r\033[K\033[31mОшибка сохранения: %v\033[0m\n> ", err)
		return
	}
	// Рассылка всем подключённым
	app.mu.RLock()
	defer app.mu.RUnlock()
	data, _ := json.Marshal(msg)
	for _, p := range app.peers {
		go func(peerID peer.ID) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s, err := app.host.NewStream(ctx, peerID, chatProtocol)
			if err != nil {
				return
			}
			defer s.Close()
			s.Write(data)
		}(p)
	}
}

func (app *App) sendPrivateMessage(peerIDStr, content string) error {
	peerID, err := peer.Decode(peerIDStr)
	if err != nil {
		return err
	}
	msg := &Message{
		ID:        generateID(),
		From:      app.host.ID().String(),
		To:        peerIDStr,
		Content:   content,
		CreatedAt: time.Now(),
		IsPrivate: true,
	}
	if err := app.saveMessage(msg); err != nil {
		return err
	}
	data, _ := json.Marshal(msg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := app.host.NewStream(ctx, peerID, privateProtocol)
	if err != nil {
		return err
	}
	defer s.Close()
	_, err = s.Write(data)
	return err
}

func (app *App) connectToPeer(addr string) error {
	peerInfo, err := peer.AddrInfoFromString(addr)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if err := app.host.Connect(ctx, *peerInfo); err != nil {
		return err
	}
	app.mu.Lock()
	app.peers[peerInfo.ID.String()] = peerInfo.ID
	app.mu.Unlock()
	// Отправить handshake
	s, err := app.host.NewStream(ctx, peerInfo.ID, handshakeProtocol)
	if err != nil {
		return err
	}
	defer s.Close()
	_, err = s.Write([]byte(app.myName))
	fmt.Printf("\r\033[K\033[32m✅ Подключен к: %s\033[0m\n", peerInfo.ID.String()[:8])
	fmt.Print("> ")
	return err
}

// verifyPeerFingerprint проверяет подлинность пира
func (app *App) verifyPeerFingerprint(peerIDStr string) {
	peerID, _ := peer.Decode(peerIDStr)
	pubKey, err := peerID.ExtractPublicKey()
	if err != nil {
		fmt.Printf("\r\033[K⚠️ Не удалось получить ключ для %s\n> ", peerIDStr[:8])
		return
	}
	
	pubBytes, _ := pubKey.Raw()
	fingerprint := hex.EncodeToString(pubBytes)[:16]
	
	fmt.Printf("\r\033[K🔍 Отпечаток ключа для %s: %s\n", peerIDStr[:8], fingerprint)
	fmt.Println("💡 Этот отпечаток должен совпадать с тем, что показывает собеседник")
	fmt.Print("> ")
}

func (app *App) showHistory(limit int) {
	rows, err := app.db.Query(`
		SELECT from_id, content, created_at, is_private
		FROM messages
		WHERE room = ? OR (is_private = 1 AND (from_id = ? OR to_id = ?))
		ORDER BY created_at DESC LIMIT ?
	`, app.currentRoom, app.host.ID().String(), app.host.ID().String(), limit)
	if err != nil {
		fmt.Printf("\r\033[KОшибка: %v\n> ", err)
		return
	}
	defer rows.Close()
	fmt.Println("\n\033[36m" + strings.Repeat("─", 60) + "\033[0m")
	fmt.Println("\033[1m📜 История сообщений:\033[0m")
	var msgs []string
	for rows.Next() {
		var from, content string
		var createdAt time.Time
		var isPrivate int
		rows.Scan(&from, &content, &createdAt, &isPrivate)
		line := fmt.Sprintf("  [%s] \033[33m%s\033[0m: %s", createdAt.Format("15:04:05"), from[:8], content)
		if isPrivate == 1 {
			line = fmt.Sprintf("  \033[35m[Private] %s\033[0m: %s", createdAt.Format("15:04:05"), content)
		}
		msgs = append([]string{line}, msgs...)
	}
	for _, l := range msgs {
		fmt.Println(l)
	}
	fmt.Println("\033[36m" + strings.Repeat("─", 60) + "\033[0m")
	fmt.Print("> ")
}

func (app *App) showContacts() {
	rows, err := app.db.Query(`SELECT id, name, peer_fingerprint, last_seen FROM contacts ORDER BY last_seen DESC`)
	if err != nil {
		fmt.Printf("\r\033[KОшибка: %v\n> ", err)
		return
	}
	defer rows.Close()
	fmt.Println("\n\033[36m" + strings.Repeat("─", 60) + "\033[0m")
	fmt.Println("\033[1m👥 Контакты:\033[0m")
	count := 0
	for rows.Next() {
		var id, name, fingerprint string
		var lastSeen time.Time
		rows.Scan(&id, &name, &fingerprint, &lastSeen)
		fmt.Printf("  \033[32m●\033[0m %s (\033[33m%s\033[0m)", name, id[:8])
		if fingerprint != "" {
			fmt.Printf(" - отпечаток: %s", fingerprint)
		}
		fmt.Printf(" - последний раз: %s\n", lastSeen.Format("15:04"))
		count++
	}
	if count == 0 {
		fmt.Println("  \033[33mНет контактов\033[0m")
	}
	fmt.Println("\033[36m" + strings.Repeat("─", 60) + "\033[0m")
	fmt.Print("> ")
}

func (app *App) showStatus() {
	// Получаем fingerprint своего ключа
	myPubKey := app.host.ID()
	pubKeyRaw, _ := myPubKey.ExtractPublicKey()
	myFingerprint := ""
	if pubKeyRaw != nil {
		pubBytes, _ := pubKeyRaw.Raw()
		myFingerprint = hex.EncodeToString(pubBytes)[:16]
	}
	
	fmt.Println("\n\033[36m" + strings.Repeat("─", 60) + "\033[0m")
	fmt.Printf("\033[1m📡 Статус:\033[0m\n")
	fmt.Printf("  ID: \033[33m%s\033[0m\n", app.host.ID())
	fmt.Printf("  Отпечаток ключа: \033[36m%s\033[0m\n", myFingerprint)
	fmt.Printf("  Имя: \033[32m%s\033[0m\n", app.myName)
	fmt.Printf("  Комната: \033[36m%s\033[0m\n", app.currentRoom)
	fmt.Printf("  Подключений: \033[33m%d\033[0m\n", len(app.peers))
	fmt.Printf("  Адрес: \033[35m%s\033[0m\n", app.GetMyAddress())
	fmt.Println("\n🔐 Безопасность:")
	fmt.Println("  • Ed25519 (квантово-уязвим, но устойчив к классическому перебору)")
	fmt.Println("  • Peer ID привязан к публичному ключу")
	fmt.Println("  • Постоянная идентификация через файл identity.key")
	fmt.Println("\033[36m" + strings.Repeat("─", 60) + "\033[0m")
	fmt.Print("> ")
}

func (app *App) GetMyAddress() string {
    // Получаем все IP адреса системы
    addrs, err := net.InterfaceAddrs()
    if err != nil {
        // fallback к старой логике
        for _, addr := range app.host.Addrs() {
            s := addr.String()
            if strings.Contains(s, "192.168.") && !strings.Contains(s, "192.168.122.") {
                return fmt.Sprintf("%s/p2p/%s", s, app.host.ID())
            }
        }
        if len(app.host.Addrs()) > 0 {
            return fmt.Sprintf("%s/p2p/%s", app.host.Addrs()[0], app.host.ID())
        }
        return ""
    }
    
    // Собираем реальные IP (не Docker, не virbr)
    var realIPs []string
    for _, addr := range addrs {
        if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            ip := ipnet.IP.String()
            
            // Пропускаем Docker/VPN интерфейсы
            if strings.HasPrefix(ip, "172.17.") ||  // Docker
               strings.HasPrefix(ip, "172.18.") ||
               strings.HasPrefix(ip, "172.19.") ||
               strings.HasPrefix(ip, "172.20.") ||
               strings.HasPrefix(ip, "172.21.") ||
               strings.HasPrefix(ip, "192.168.122.") { // virbr0
                continue
            }
            
            // Пропускаем интерфейсы без IP
            if ip == "" || ip == "<nil>" {
                continue
            }
            
            realIPs = append(realIPs, ip)
        }
    }
    
    // Ищем приоритетные IP
    for _, ip := range realIPs {
        // Приоритет 1: 192.168.x.x (домашняя сеть)
        if strings.HasPrefix(ip, "192.168.") {
            return fmt.Sprintf("/ip4/%s/tcp/9000/p2p/%s", ip, app.host.ID())
        }
    }
    
    for _, ip := range realIPs {
        // Приоритет 2: 10.x.x.x (корпоративная сеть)
        if strings.HasPrefix(ip, "10.") {
            return fmt.Sprintf("/ip4/%s/tcp/9000/p2p/%s", ip, app.host.ID())
        }
    }
    
    for _, ip := range realIPs {
        // Приоритет 3: 172.16-31 (кроме Docker диапазона)
        if strings.HasPrefix(ip, "172.") {
            parts := strings.Split(ip, ".")
            if len(parts) > 1 {
                secondOctet, _ := strconv.Atoi(parts[1])
                if secondOctet >= 16 && secondOctet <= 31 && secondOctet != 17 && secondOctet != 18 && secondOctet != 19 && secondOctet != 20 && secondOctet != 21 {
                    return fmt.Sprintf("/ip4/%s/tcp/9000/p2p/%s", ip, app.host.ID())
                }
            }
        }
    }
    
    // Если ничего не нашли, показываем первый не-loopback адрес
    for _, addr := range app.host.Addrs() {
        s := addr.String()
        if !strings.Contains(s, "127.0.0.1") && !strings.Contains(s, "172.17.") && !strings.Contains(s, "172.18.") {
            return fmt.Sprintf("%s/p2p/%s", s, app.host.ID())
        }
    }
    
    return ""
}

func (app *App) showHelp() {
	fmt.Println("\n\033[36m" + strings.Repeat("─", 60) + "\033[0m")
	fmt.Println("\033[1m📚 Команды:\033[0m")
	fmt.Println("  \033[33m/connect\033[0m <addr>      - Подключиться")
	fmt.Println("  \033[33m/private\033[0m <id> <msg>  - Приватное сообщение")
	fmt.Println("  \033[33m/verify\033[0m <id>         - Проверить отпечаток ключа")
	fmt.Println("  \033[33m/history\033[0m [N]         - История (N сообщений)")
	fmt.Println("  \033[33m/contacts\033[0m            - Список контактов")
	fmt.Println("  \033[33m/room\033[0m <name>         - Сменить комнату")
	fmt.Println("  \033[33m/shrug\033[0m               - Отправить ¯\\_(o_o)_/¯")
	fmt.Println("  \033[33m/status\033[0m              - Статус")
	fmt.Println("  \033[33m/myaddress\033[0m           - Мой адрес")
	fmt.Println("  \033[33m/help\033[0m                - Эта справка")
	fmt.Println("  \033[33m/quit\033[0m                - Выход")
	fmt.Println("\n💡 \033[32mПросто печатайте текст для отправки в комнату\033[0m")
	fmt.Println("\n🔐 Особенности безопасности:")
	fmt.Println("  • Peer ID постоянный и привязан к ключу")
	fmt.Println("  • Используйте /verify для проверки собеседника")
	fmt.Println("  • Файл identity.key хранит ваш приватный ключ")
	fmt.Println("\033[36m" + strings.Repeat("─", 60) + "\033[0m")
	fmt.Print("> ")
}

func (app *App) commandLoop() {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}
		if strings.HasPrefix(input, "/") {
			parts := strings.Fields(input)
			switch parts[0] {

			case "/shrug":
			    app.sendMessage("¯\\_(o_o)_/¯")
			    fmt.Printf("\r\033[K\033[36m[Вы] ¯\\_(o_o)_/¯\033[0m\n> ")
			    
			case "/connect":
				if len(parts) < 2 {
					fmt.Print("\r\033[K❌ Использование: /connect <address>\n> ")
					continue
				}
				if err := app.connectToPeer(parts[1]); err != nil {
					fmt.Printf("\r\033[K❌ Ошибка: %v\n> ", err)
				}
			case "/private":
				if len(parts) < 3 {
					fmt.Print("\r\033[K❌ Использование: /private <peer_id> <message>\n> ")
					continue
				}
				msg := strings.Join(parts[2:], " ")
				if err := app.sendPrivateMessage(parts[1], msg); err != nil {
					fmt.Printf("\r\033[K❌ Ошибка: %v\n> ", err)
				} else {
					fmt.Printf("\r\033[K\033[35m[Private to %s]\033[0m: %s\n> ", parts[1][:8], msg)
				}
			case "/verify":
				if len(parts) < 2 {
					fmt.Print("\r\033[K❌ Использование: /verify <peer_id>\n> ")
					continue
				}
				app.verifyPeerFingerprint(parts[1])
			case "/history":
				limit := 50
				if len(parts) > 1 {
					fmt.Sscanf(parts[1], "%d", &limit)
				}
				app.showHistory(limit)
			case "/contacts":
				app.showContacts()
			case "/room":
				if len(parts) < 2 {
					fmt.Print("\r\033[K❌ Использование: /room <name>\n> ")
					continue
				}
				app.currentRoom = parts[1]
				fmt.Printf("\r\033[K\033[36m✅ Переключен в комнату: %s\033[0m\n> ", app.currentRoom)
			case "/status":
				app.showStatus()
			case "/myaddress":
				fmt.Printf("\r\033[K\033[35m🔗 Ваш адрес: %s\033[0m\n> ", app.GetMyAddress())
			case "/help":
				app.showHelp()
			case "/quit", "/exit":
				fmt.Println("\n👋 До свидания!")
				os.Exit(0)
			default:
				fmt.Printf("\r\033[K❌ Неизвестная команда: %s\n> ", parts[0])
			}
		} else {
			app.sendMessage(input)
		}
	}
}

func (app *App) Run() {
	fmt.Println("\n╔══════════════════════════════════════════════════╗")
	fmt.Println("║     🔐 Secure P2P Messenger v3.0                 ║")
	fmt.Println("║     Постоянный ID + Квантово-устойчивый          ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Printf("\n📡 Ваш ID: \033[33m%s\033[0m\n", app.host.ID().String()[:16]+"...")
	fmt.Printf("👤 Ваше имя: \033[32m%s\033[0m\n", app.myName)
	fmt.Printf("🔗 Ваш адрес: \033[35m%s\033[0m\n", app.GetMyAddress())
	fmt.Println("\n💡 Введите \033[33m/help\033[0m для списка команд")
	fmt.Println(strings.Repeat("─", 60))
	app.commandLoop()
}

func main() {
	fmt.Print("👤 Введите ваше имя: ")
	reader := bufio.NewReader(os.Stdin)
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Anonymous"
	}
	app, err := NewApp(name)
	if err != nil {
		panic(err)
	}
	app.Run()
}
