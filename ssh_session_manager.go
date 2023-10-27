package arkssh

import (
	"sync"
	"time"
)

var (
	HuaweiNoPage  = "screen-length 0 temporary"
	H3cNoPage     = "screen-length disable"
	CiscoNoPage   = "terminal length 0"
	SangforNoPage = "terminal length 0"
	DiPuNoPage    = "terminal line 0"
	ZTENoPage     = "terminal length 0"
	AnshiNoPage   = ""
	LinuxNopage   = ""
)

var sessionManager = NewSessionManager()

/**
 * 创建一个SessionManager，相当于SessionManager的构造函数
 * @return SessionManager实例
 */
func NewSessionManager() *SessionManager {
	sessionManager := new(SessionManager)
	sessionManager.sessionCache = make(map[string]*SSHSession, 0)
	sessionManager.sessionLocker = make(map[string]*sync.Mutex, 0)
	sessionManager.sessionCacheLocker = new(sync.RWMutex)
	sessionManager.sessionLockerMapLocker = new(sync.RWMutex)
	//启动自动清理的线程，清理10分钟未使用的session缓存
	sessionManager.RunAutoClean()
	return sessionManager
}

/**
 * session（SSHSession）的管理类，会统一缓存打开的session，自动处理未使用超过10分钟的session
 * @attr sessionCache:缓存所有打开的map（10分钟内使用过的），sessionLocker设备锁，globalLocker全局锁
 */
type SessionManager struct {
	sessionCache           map[string]*SSHSession
	sessionLocker          map[string]*sync.Mutex
	sessionCacheLocker     *sync.RWMutex
	sessionLockerMapLocker *sync.RWMutex
}

func (s *SessionManager) SetSessionCache(sessionKey string, session *SSHSession) {
	s.sessionCacheLocker.Lock()
	defer s.sessionCacheLocker.Unlock()
	s.sessionCache[sessionKey] = session
}

func (s *SessionManager) GetSessionCache(sessionKey string) *SSHSession {
	s.sessionCacheLocker.RLock()
	defer s.sessionCacheLocker.RUnlock()
	cache, ok := s.sessionCache[sessionKey]
	if ok {
		return cache
	} else {
		return nil
	}
}

/**
 * 给指定的session上锁
 * @param  sessionKey:session的索引键值
 */
func (s *SessionManager) LockSession(sessionKey string) {
	s.sessionLockerMapLocker.RLock()
	mutex, ok := s.sessionLocker[sessionKey]
	s.sessionLockerMapLocker.RUnlock()
	if !ok {
		//如果获取不到锁，需要创建锁，主要更新锁存的时候需要上全局锁
		mutex = new(sync.Mutex)
		s.sessionLockerMapLocker.Lock()
		s.sessionLocker[sessionKey] = mutex
		s.sessionLockerMapLocker.Unlock()
	}
	mutex.Lock()
}

/**
 * 给指定的session解锁
 * @param  sessionKey:session的索引键值
 */
func (s *SessionManager) UnlockSession(sessionKey string) {
	s.sessionLockerMapLocker.RLock()
	s.sessionLocker[sessionKey].Unlock()
	s.sessionLockerMapLocker.RUnlock()
}

/**
 * 更新session缓存中的session，连接设备，打开会话，初始化会话（等待登录，识别设备类型，执行禁止分页），添加到缓存
 * @param  user ssh连接的用户名, password 密码, ipPort 交换机的ip和端口
 * @return 执行的错误
 */
func (s *SessionManager) updateSession(user, password, ipPort, brand string) error {
	sessionKey := user + "_" + password + "_" + ipPort
	mySession, err := NewSSHSession(user, password, ipPort)
	if err != nil {
		LogDebug("NewSSHSession err:%s", err.Error())
		return err
	}
	//初始化session，包括等待登录输出和禁用分页
	s.initSession(mySession, brand)
	//更新session的缓存
	s.SetSessionCache(sessionKey, mySession)
	return nil
}

/**
 * 初始化会话（等待登录，识别设备类型，执行禁止分页）
 * @param  session:需要执行初始化操作的SSHSession
 */
func (s *SessionManager) initSession(session *SSHSession, brand string) {
	if brand == "" {
		LogDebug("brand不存在，自动获取brand中")
		//如果传入的设备型号不匹配则自己获取
		brand = session.GetSSHBrand()
	}
	switch brand {
	case HUAWEI:
		session.WriteChannel(HuaweiNoPage)
		break
	case H3C:
		session.WriteChannel(H3cNoPage)
		break
	case SANGFOR:
		session.WriteChannel(SangforNoPage)
		break
	case AnShi:
		session.WriteChannel(AnshiNoPage)
		break
	case CISCO:
		session.WriteChannel(CiscoNoPage)
		break
	case LINUX:
		session.WriteChannel(LinuxNopage)
		break
	case ZTE:
		session.WriteChannel(ZTENoPage)
		break
	case "":
		session.WriteChannel(HuaweiNoPage, H3cNoPage, SangforNoPage, DiPuNoPage)
	default:
		return
	}
	session.ReadChannelTiming(5)
}

/**
 * 从缓存中获取session。如果不存在或者不可用，则重新创建
 * @param  user ssh连接的用户名, password 密码, ipPort 交换机的ip和端口
 * @return SSHSession
 */
func (s *SessionManager) GetSession(user, password, ipPort, brand string) (*SSHSession, error) {
	sessionKey := user + "_" + password + "_" + ipPort
	session := s.GetSessionCache(sessionKey)
	if session != nil {
		//返回前要验证是否可用，不可用要重新创建并更新缓存
		if session.CheckSelf() {
			LogDebug("-----GetSession from cache-----")
			session.UpdateLastUseTime()
			return session, nil
		}
		LogDebug("Check session failed")
	}
	//如果不存在或者验证失败，需要重新连接，并更新缓存
	if err := s.updateSession(user, password, ipPort, brand); err != nil {
		LogDebug("SSH session pool updateSession err:%s", err.Error())
		return nil, err
	} else {
		return s.GetSessionCache(sessionKey), nil
	}
}

/**
 * 开始自动清理session缓存中未使用超过10分钟的session
 */
func (s *SessionManager) RunAutoClean() {
	go func() {
		for {
			timeoutSessionIndex := s.getTimeoutSessionIndex()
			s.sessionCacheLocker.Lock()
			for _, sessionKey := range timeoutSessionIndex {
				//s.LockSession(sessionKey)
				delete(s.sessionCache, sessionKey)
				//s.UnlockSession(sessionKey)
			}
			s.sessionCacheLocker.Unlock()
			time.Sleep(30 * time.Second)
		}
	}()
}

/**
 * 获取所有超时（10分钟未使用）session在cache的sessionKey
 * @return []string 所有超时的sessionKey数组
 */
func (s *SessionManager) getTimeoutSessionIndex() []string {
	timeoutSessionIndex := make([]string, 0)
	s.sessionCacheLocker.RLock()
	defer func() {
		s.sessionCacheLocker.RUnlock()
		if err := recover(); err != nil {
			LogDebug("SSHSessionManager getTimeoutSessionIndex err:%s", err)
		}
	}()
	for sessionKey, SSHSession := range s.sessionCache {
		timeDuratime := time.Now().Sub(SSHSession.GetLastUseTime())
		if timeDuratime.Minutes() > 9 {
			LogDebug("RunAutoClean close session<%s, unuse time=%s>", sessionKey, timeDuratime.String())
			SSHSession.Close()
			timeoutSessionIndex = append(timeoutSessionIndex, sessionKey)
		}
	}
	return timeoutSessionIndex
}
