package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"io/ioutil"
	"crypto/md5"
	"encoding/hex"
	"strings"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"syscall"
)

const (
	ServerShutDownCommand = byte('b')
	ServersGetCommand     = byte('1')
	DefaultGamePort       = 27010
	defaultURL            = "https://raw.githubusercontent.com/geckomd/lvms/gh-pages/servers.txt"
	suFile                = "su.txt"
	localServers          = "servers.txt"
	userAgent             = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/114.0"
	checkInterval         = 1 * time.Minute // Интервал проверки списка серверов
	memoryLimit    	      = 10 * 1024 * 1024 // 10MB
	S_OK 				  = 0
	expectedHash          = "9530a2cf1c4c0fb160206153d8758c0f" // rev_MasterServers.vdf
	appExe                = "hl.exe"
)

type MasterServer struct {
	servers              []*net.UDPAddr
	socket               *net.UDPConn
	gameID               int
	isServerListComplete bool
	isServerListReady    bool // Флаг готовности списка серверов
}

func NewMasterServer(gameID int) *MasterServer {
	return &MasterServer{
		servers:              []*net.UDPAddr{},
		gameID:               gameID,
		isServerListComplete: false,
		isServerListReady:    false,
	}
}

func (s *MasterServer) Create(address string, port int) error {
	serverAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", address, port))
	if err != nil {
		// return fmt.Errorf("ошибка разрешения UDP-адреса: %w", err)
		return err
	}

	conn, err := net.ListenUDP("udp4", serverAddr)
	if err != nil {
		// return fmt.Errorf("ошибка прослушивания UDP: %w", err)
		return err
	}

	s.socket = conn
	return nil
}

func (s *MasterServer) Close() {
	if s.socket != nil {
		err := s.socket.Close()
		if err != nil {
			// log.Printf("Ошибка закрытия сокета: %v", err)
		}
		s.socket = nil
	}
}

func (s *MasterServer) Read(bufferSize int) ([]byte, net.Addr, error) {
	buffer := make([]byte, bufferSize)
	n, addr, err := s.socket.ReadFromUDP(buffer)
	if err != nil {
		if err == io.EOF {
			return nil, nil, err
		}
		// return nil, nil, fmt.Errorf("ошибка чтения из сокета: %w", err)
		return nil, nil, err
	}

	return buffer[:n], addr, nil
}


func (s *MasterServer) Send(address string, port int, message []byte) error {
	serverAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", address, port))
	if err != nil {
		// return fmt.Errorf("ошибка разрешения UDP-адреса: %w", err)
		return err
	}

	_, err = s.socket.WriteToUDP(message, serverAddr)
	if err != nil {
		// return fmt.Errorf("ошибка отправки UDP-сообщения: %w", err)
		return err
	}

	return nil
}

func (s *MasterServer) BeforeProcessing(clientAddr net.Addr) {
	// Выполните все необходимые проверки или операции перед обработкой запроса клиента.
}

func (s *MasterServer) RequestUnprocessed(clientAddr net.Addr) {
	// Обработка любых необработанных запросов от клиентов
}

func (s *MasterServer) Listen() {
	for {
		buffer, clientAddr, err := s.Read(4096)
		if err != nil {
			// log.Printf("Ошибка чтения из сокета: %v", err)
			continue
		}

		s.BeforeProcessing(clientAddr)

		if buffer[0] == ServerShutDownCommand {
			if s.isServerListReady { // Проверяем флаг готовности списка серверов
				s.RemoveServer(clientAddr.(*net.UDPAddr))
			}
		} else if buffer[0] == ServersGetCommand {
			if s.isServerListReady { // Проверяем флаг готовности списка серверов
				serverList := s.GetServerList()

				response := append([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x66, 0x0A}, serverList...)
				if udpAddr, ok := clientAddr.(*net.UDPAddr); ok {
					err := s.Send(udpAddr.IP.String(), udpAddr.Port, response)
					if err != nil {
						// log.Printf("Ошибка отправки ответа: %v", err)
					}
				} else {
					// log.Println("Недопустимый тип адреса клиента")
				}

				if s.isServerListComplete {
					s.Close()
					break
				}
			}
		} else {
			s.RequestUnprocessed(clientAddr)
		}
	}
}

func (s *MasterServer) AddServer(serverAddr *net.UDPAddr) {
	s.servers = append(s.servers, serverAddr)
	// fmt.Println(serverAddr.String())
}

func (s *MasterServer) RemoveServer(serverAddr *net.UDPAddr) {
	for i, addr := range s.servers {
		if addr.String() == serverAddr.String() {
			s.servers = append(s.servers[:i], s.servers[i+1:]...)
			// log.Println("Удаленный сервер:", serverAddr.String())
			break
		}
	}
}

func (s *MasterServer) GetServerList() []byte {
	serverList := make([]byte, 0, len(s.servers)*6)

	for _, serverAddr := range s.servers {
		serverEntry := s.createServerEntry(serverAddr)
		if serverEntry != nil {
			serverList = append(serverList, serverEntry...)
		}
	}

	return serverList
}

func (s *MasterServer) createServerEntry(serverAddr *net.UDPAddr) []byte {
	ip := serverAddr.IP.To4()
	if ip == nil {
		// log.Printf("Неверный IP-адрес: %s", serverAddr.IP.String())
		return nil
	}

	portInt := s.gameID + DefaultGamePort

	if serverAddr.Port != 0 {
		portInt = serverAddr.Port
	}

	serverEntry := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x66, 0x0A}
	serverEntry = append(serverEntry, ip...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(portInt))
	serverEntry = append(serverEntry, portBytes...)

	return serverEntry
}

func LoadServersFromFileWithMemoryLimit(filename string, maxMemorySize int64) ([]*net.UDPAddr, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	servers := make([]*net.UDPAddr, 0)
	var totalSize int64

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		addr, err := net.ResolveUDPAddr("udp4", line)
		if err != nil {
			// log.Printf("Ошибка разрешения UDP-адреса: %v", err)
			continue
		}

		serverSize := int64(binary.Size(addr.IP) + 2) // Определение размера сервера в байтах
		if totalSize+serverSize > maxMemorySize {
			break // Прекращаем загрузку, если достигнут предельный размер памяти
		}

		servers = append(servers, addr)
		totalSize += serverSize
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return servers, nil
}

func CheckFileModification(filename string, lastModifiedTime time.Time) (bool, error) {
	fileInfo, err := os.Stat(filename)
	if err != nil {
		// return false, fmt.Errorf("ошибка получения информации о файле: %w", err)
		return false, err
	}

	currentModifiedTime := fileInfo.ModTime()
	if currentModifiedTime.After(lastModifiedTime) {
		return true, nil
	}

	return false, nil
}

// Проверяет файл с адресом мастер-сервера
func checkAndUpdateFile() {
	// Получение абсолютного пути к текущему файлу
	absPath, err := filepath.Abs(os.Args[0])
	if err != nil {
		// Ошибка при получении абсолютного пути
		return
	}

	// Построение относительного пути к файлу config/rev_MasterServers.vdf
	dir := filepath.Dir(absPath)
	filePathMS := filepath.Join(dir, "config", "rev_MasterServers.vdf")

	// Проверка наличия файла
	if _, err := os.Stat(filePathMS); err == nil {
		// Файл существует
		fileInfo, err := os.Stat(filePathMS)
		if err != nil {
			// Ошибка при получении информации о файле
			return
		}

		// Проверка флага доступа (только чтение)
		if fileInfo.Mode().Perm()&os.FileMode(0400) != 0 {
			// Файл доступен только для чтения
			// Изменение режима файла на 0644
			err = os.Chmod(filePathMS, 0644)
			if err != nil {
				// Ошибка изменения режима файла
				return
			}
		}

		// Чтение содержимого файла
		content, err := ioutil.ReadFile(filePathMS)
		if err != nil {
			// Ошибка чтения файла
			return
		}

		// Запись обновленного содержимого файла
		err = ioutil.WriteFile(filePathMS, content, 0644)
		if err != nil {
			// Ошибка обновления файла
			return
		}

		// Изменение режима файла на 0644
		err = os.Chmod(filePathMS, 0644)
		if err != nil {
			// Ошибка изменения режима файла
			return
		}

		// Проверка md5 хеша файла
		hasher := md5.New()
		hasher.Write(content)
		actualHash := hex.EncodeToString(hasher.Sum(nil))

		if actualHash != expectedHash {
			// Обновление файла с заданным содержимым
			newContent := []byte(`"MasterServers"
{
"hl1"
{
	"0"
	{
		"addr"	"127.0.0.1:27010"
	}
}
}`)

			err = ioutil.WriteFile(filePathMS, newContent, 0644)
			if err != nil {
				// Ошибка обновления файла
				return
			}

			// Изменение режима файла на 0644
			err = os.Chmod(filePathMS, 0644)
			if err != nil {
				// Ошибка изменения режима файла
				return
			}

			// Хеши не совпадают. Файл был обновлен.
		} else {
			// Хеши совпадают. Файл не требует обновления.
		}
	} else if os.IsNotExist(err) {
		// Файл не существует, создаем новый файл
		newContent := []byte(`"MasterServers"
{
"hl1"
{
	"0"
	{
		"addr"	"127.0.0.1:27010"
	}
}
}`)

		err = ioutil.WriteFile(filePathMS, newContent, 0644)
		if err != nil {
			// Ошибка создания файла
			return
		}

		// Изменение режима файла на 0644
		err = os.Chmod(filePathMS, 0644)
		if err != nil {
			// Ошибка изменения режима файла
			return
		}

		// Файл был создан.
	} else {
		// Ошибка при проверке файла
		return
	}
}

func readServerURLs() ([]string, error) {
	file, err := os.Open(suFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	reader := io.Reader(file)
	content, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			urls = append(urls, line)
		}
	}

	if len(urls) == 0 || !checkServerAvailability(urls) {
		urls = append(urls, defaultURL)
	}

	return urls, nil
}

func checkServerAvailability(urls []string) bool {
	for _, url := range urls {
		resp, err := http.Head(url)
		if err != nil {
			// log.Printf("Ошибка проверки доступности сервера: %v", err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return true
		}
	}

	return false
}

func checkServers(urls []string) {
	localHash := ""
	for {
		for _, url := range urls {
			// Создание клиента и установка заголовка User-Agent
			client := &http.Client{}
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				// log.Printf("Ошибка создания HTTP-запроса: %v", err)
				continue
			}
			req.Header.Set("User-Agent", userAgent)

			resp, err := client.Do(req)
			if err != nil {
				// log.Printf("Ошибка отправки HTTP-запроса: %v", err)
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				// log.Printf("Сервер %s доступен", url)

				// Проверка наличия файла на удаленном сервере
				if resp.Header.Get("Content-Type") != "text/html" {
					// Файл существует, получаем хеш удаленного файла
					body, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						// log.Printf("Ошибка чтения удаленного файла: %v", err)
						continue
					}
					remoteHash := md5.Sum(body)

					// Проверка наличия и актуальности локальной копии файла servers.txt
					localFile, err := ioutil.ReadFile(localServers)
					if err != nil {
						if os.IsNotExist(err) {
							// log.Printf("Локальный файл не существует")

							// Загрузка внешней версии файла
							// log.Printf("Загрузка файла с: %s", url)
							fileResp, err := client.Get(url)
							if err != nil {
								// log.Printf("Ошибка загрузки файла: %v", err)

								// Создаем пустой файл с адресом по умолчанию
								err := ioutil.WriteFile(localServers, []byte("127.0.0.1:27015"), 0644)
								if err != nil {
									// log.Printf("Ошибка создания локального файла: %v", err)
									continue
								}
								// log.Println("Пустой файл, созданный с адресом по умолчанию")
								continue
							}
							defer fileResp.Body.Close()

							// Создание или перезапись локальной копии файла servers.txt
							file, err := os.Create(localServers)
							if err != nil {
								// log.Printf("Ошибка создания локального файла: %v", err)
								continue
							}
							defer file.Close()

							_, err = io.Copy(file, fileResp.Body)
							if err != nil {
								// log.Printf("Ошибка сохранения файла: %v", err)
								continue
							}

							localHash = hex.EncodeToString(remoteHash[:]) // Обновление хеша локального файла
							// log.Println("Файл успешно загружен")
							continue
						} else {
							// log.Printf("Ошибка проверки локального файла: %v", err)
							continue
						}
					}

					localHashBytes := md5.Sum(localFile)
					localHash = hex.EncodeToString(localHashBytes[:])

					// Проверка режима файла
					fileInfo, err := os.Stat(localServers)
					if err != nil {
						// log.Printf("Ошибка получения информации о файле: %v", err)
						continue
					}

					if fileInfo.Mode().Perm()&os.ModePerm != 0644 {
						// Файл имеет другой режим, изменяем его на 0644
						err := os.Chmod(localServers, 0644)
						if err != nil {
							// log.Printf("Ошибка изменения режима файла: %v", err)
							continue
						}
						// log.Println("Режим файла изменен на 0644")
					}

					// Сравнение хешей с локальным файлом
					if hex.EncodeToString(remoteHash[:]) != localHash {
						// Загрузка новой версии файла servers.txt с удаленного сервера
						// log.Printf("Загрузка обновленного файла с: %s", url)
						fileResp, err := client.Get(url)
						if err != nil {
							// log.Printf("Ошибка загрузки файла: %v", err)
							continue
						}
						defer fileResp.Body.Close()

						// Замена локальной копии файла servers.txt
						file, err := os.Create(localServers)
						if err != nil {
							// log.Printf("Ошибка создания локального файла: %v", err)
							continue
						}
						defer file.Close()

						_, err = io.Copy(file, fileResp.Body)
						if err != nil {
							// log.Printf("Ошибка сохранения файла: %v", err)
							continue
						}

						localHash = hex.EncodeToString(remoteHash[:]) // Обновление хеша локального файла
						// log.Println("Файл успешно обновлен")
					} else {
						// log.Println("Локальный файл обновлен")
					}
				} else {
					// log.Printf("Файл не существует на сервере: %s", url)
				}
			} else {
				// log.Printf("Сервер %s недоступен", url)
			}
		}

		time.Sleep(checkInterval) // Интервал проверки
	}
}

// Отключение оптимизации во весь экран
func disableFullscreenOptimization() {
	user32 := syscall.NewLazyDLL("user32.dll")
	setProcessDPIAware := user32.NewProc("SetProcessDPIAware")

	_, _, _ = setProcessDPIAware.Call()
}

func main() {

	// Отключить полноэкранную оптимизацию
	disableFullscreenOptimization()

	// Проверяет файл с адресом мастер-сервера 
	checkAndUpdateFile()

	// Проверка наличия файла su.txt
	_, err := os.Stat(suFile)
	if err != nil {
		if os.IsNotExist(err) {
			// Если файл su.txt не существует, создаем его
			err := ioutil.WriteFile(suFile, nil, 0644)
			if err != nil {
				//fmt.Println("Не удалось создать файл su.txt:", err)
				return
			}
		} else {
			// fmt.Println("Ошибка при получении информации о файле su.txt:", err)
			return
		}
	}

	// Проверяем атрибуты файла su.txt
	fileInfo, err := os.Stat(suFile)
	if err != nil {
		// fmt.Println("Ошибка при получении информации о файле su.txt:", err)
		return
	}
	if fileInfo.Mode().Perm()&0400 != 0 {
		// Если файл доступен только для чтения, изменяем атрибуты на обычные
		err := os.Chmod(suFile, 0644)
		if err != nil {
			// fmt.Println("Не удалось разблокировать файл su.txt:", err)
			return
		}
	}

	// Проверка наличия файла servers.txt
	_, err = os.Stat(localServers)
	if err != nil {
		if os.IsNotExist(err) {
			// Если файл servers.txt не существует, создаем его
			err := ioutil.WriteFile(localServers, nil, 0644)
			if err != nil {
				//fmt.Println("Не удалось создать файл servers.txt:", err)
				return
			}
		} else {
			// fmt.Println("Ошибка при получении информации о файле servers.txt:", err)
			return
		}
	}

	// Проверяем атрибуты файла servers.txt
	fileInfo, err = os.Stat(localServers)
	if err != nil {
		// fmt.Println("Ошибка при получении информации о файле servers.txt:", err)
		return
	}

	if fileInfo.Mode().Perm()&0400 != 0 {
		// Если файл доступен только для чтения, изменяем атрибуты на обычные
		err := os.Chmod(localServers, 0644)
		if err != nil {
			// fmt.Println("Не удалось разблокировать файл servers.txt:", err)
			return
		}
	}

	// Загрузка адресов проверки файла servers.txt из файла su.txt
	urls, err := readServerURLs()
	if err != nil {
		// fmt.Println("Не удалось загрузить адреса серверов из файла su.txt:", err)
		return
	}

	// Запуск горутины для проверки файлов servers.txt на удаленных серверах
	go checkServers(urls)

	server := NewMasterServer(1000)
	err = server.Create("127.0.0.1", 27010)
	if err != nil {
		// log.Printf("Ошибка создания сервера: %v", err)
		os.Exit(1)
	}

	servers, err := LoadServersFromFileWithMemoryLimit(localServers, memoryLimit)
	if err != nil {
		// log.Printf("Ошибка загрузки серверов из файла: %v", err)
		os.Exit(1)
	}

	server.servers            = servers
	server.isServerListReady  = true
	lastModifiedTime         := time.Now()

	// Создаем каналы для сигналов завершения
	done := make(chan struct{})
	cmdErr := make(chan error)

	// Запускаем мастер-сервер в отдельной горутине
	go func() {
		defer close(done)
		server.Listen()
	}()

	// Ожидаем изменений в файле servers.txt
	go func() {
		for {
			updated, err := CheckFileModification(localServers, lastModifiedTime)
			if err != nil {
				// log.Printf("Ошибка проверки модификации файла: %v", err)
				break
			}

			if updated {
				lastModifiedTime = time.Now()

				// Перезагрузка данных в оперативной памяти
				servers, err := LoadServersFromFileWithMemoryLimit(localServers, memoryLimit)
				if err != nil {
					// log.Printf("Ошибка загрузки серверов из файла: %v", err)
					break
				}

				server.servers = servers
				server.isServerListReady = true

				// log.Println("Список серверов обновлен")
			}

			time.Sleep(1 * time.Second)
		}
	}()

	// Определяем путь к hl.exe
	executablePath, err := os.Executable()
	if err != nil {
		// log.Printf("Ошибка получения пути к исполняемому файлу: %v", err)
		os.Exit(1)
	}

	hlExePath := filepath.Join(filepath.Dir(executablePath), appExe)
	var cmd *exec.Cmd
	// Запускаем hl.exe в отдельном процессе
	// Проверяем наличие аргументов командной строки
	if len(os.Args) > 1 {
		cmd = exec.Command(hlExePath, os.Args[1:]...)
	} else {
		// Если аргументы отсутствуют, добавляем параметр по умолчанию -game cstrike
		cmd = exec.Command(hlExePath, "-game", "cstrike")
	}

	err = cmd.Start()
	if err != nil {
		// log.Printf("Ошибка запуска hl.exe: %v", err)
		os.Exit(1)
	}

	// Ожидаем завершения hl.exe в отдельной горутине
	go func() {
		err := cmd.Wait()
		cmdErr <- err
	}()

	// Ожидаем сигнала завершения из канала done или ошибки из cmdErr
	select {
	case <-done:
		// log.Println("Мастер-сервер остановлен")
	case err := <-cmdErr:
		if err != nil {
			// log.Printf("Error running hl.exe: %v", err)
		}
	}

	// Закрываем сервер и освобождаем ресурсы
	server.Close()
}